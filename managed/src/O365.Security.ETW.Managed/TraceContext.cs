using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading;
using Microsoft.O365.Security.ETW.Interop;
using Microsoft.O365.Security.ETW.Schema;

namespace Microsoft.O365.Security.ETW
{
    /// <summary>
    /// Per-trace state and the entry point ETW calls for each event.
    /// </summary>
    /// <remarks>
    /// ProcessTrace delivers a trace's events on a single thread, so everything reachable from
    /// here is single threaded and needs no locking. Each trace owns its own scratch, schema
    /// cache and adapter for exactly that reason: sharing them per provider would break as soon
    /// as one provider were enabled on two traces.
    /// </remarks>
    internal sealed unsafe class TraceContext
    {
        private readonly EventScratch _scratch = new EventScratch();
        private readonly EventRecordAdapter _adapter = new EventRecordAdapter();

        private Provider[] _providers = Array.Empty<Provider>();
        private Guid[] _providerIds = Array.Empty<Guid>();

        private KernelProvider[] _kernelProviders = Array.Empty<KernelProvider>();
        private Guid[] _kernelProviderIds = Array.Empty<Guid>();

        public ulong EventsTotal;
        public ulong EventsHandled;
        public ulong BuffersProcessed;

        /// <summary>Whether MOF (WBEM) events are routed to providers by schema provider GUID.</summary>
        public bool MofEventsEnabled;

        /// <summary>Whether WPP events are routed to providers by schema provider GUID.</summary>
        public bool WppEventsEnabled;

        public EventRecordDelegate DefaultEventRef = null!;
        public IEventRecordDelegate DefaultEvent = null!;
        public IEventRecordMetadataDelegate DefaultMetadata = null!;
        public EventRecordErrorDelegate DefaultError = null!;

        public void SetProviders(List<Provider> providers)
        {
            _providers = providers.ToArray();
            _providerIds = new Guid[_providers.Length];

            for (int i = 0; i < _providers.Length; i++)
            {
                _providerIds[i] = _providers[i].Id;
            }
        }

        public void SetKernelProviders(List<KernelProvider> providers)
        {
            _kernelProviders = providers.ToArray();
            _kernelProviderIds = new Guid[_kernelProviders.Length];

            for (int i = 0; i < _kernelProviders.Length; i++)
            {
                _kernelProviderIds[i] = _kernelProviders[i].Id;
            }
        }

        public void OnEvent(EVENT_RECORD* record)
        {
            EventsTotal++;

            _scratch.Begin(record);
            _adapter.Begin(record, _scratch);

            try
            {
                var view = new EventRecordRef(record, _scratch);

                if (Route(view, record))
                {
                    EventsHandled++;
                }
                else
                {
                    DispatchDefault(view);
                }
            }
            finally
            {
                _adapter.End();
            }
        }

        /// <summary>
        /// Delivers the event to the first provider that claims it, mirroring
        /// krabs::details::ut::forward_events.
        /// </summary>
        /// <remarks>
        /// For manifest and TraceLogging events the header carries the provider GUID. For MOF
        /// and WPP events it carries the *message* GUID instead, so the only way to find the
        /// owning provider is to resolve the schema and read TRACE_EVENT_INFO.ProviderGuid.
        /// That lookup is gated on the trace opting in, because it forces a TDH call for
        /// every classic event whether or not anyone wants them.
        /// </remarks>
        private bool Route(in EventRecordRef view, EVENT_RECORD* record)
        {
            if (_kernelProviderIds.Length != 0)
            {
                // krabs::details::kt::forward_events matches on the header GUID alone: the
                // kernel logger stamps the real provider GUID there even though its events
                // are classic MOF, so no schema lookup is needed to route them.
                Guid kernelId = record->EventHeader.ProviderId;

                for (int i = 0; i < _kernelProviderIds.Length; i++)
                {
                    if (_kernelProviderIds[i] == kernelId)
                    {
                        _kernelProviders[i].Dispatch(view, _adapter);
                        return true;
                    }
                }

                return false;
            }

            DecodingSource type = EventRecordRef.GetEventType(record);

            if (type == DecodingSource.XMLFile || type == DecodingSource.Tlg)
            {
                Guid providerId = record->EventHeader.ProviderId;

                for (int i = 0; i < _providerIds.Length; i++)
                {
                    if (_providerIds[i] == providerId)
                    {
                        _providers[i].Dispatch(view, _adapter);
                        return true;
                    }
                }
            }
            else if ((type == DecodingSource.Wbem && MofEventsEnabled)
                || (type == DecodingSource.WPP && WppEventsEnabled))
            {
                SchemaEntry schema = view.SchemaEntry;

                if (schema.Status == NativeConstants.ERROR_SUCCESS)
                {
                    Guid providerId = schema.Info->ProviderGuid;

                    for (int i = 0; i < _providerIds.Length; i++)
                    {
                        if (_providerIds[i] == providerId)
                        {
                            _providers[i].Dispatch(view, _adapter);
                            return true;
                        }
                    }
                }
            }

            return false;
        }

        private void DispatchDefault(in EventRecordRef view)
        {
            // Same shape as Provider.Dispatch: the native default callback is the very same
            // CallbackBridge, so metadata fires unconditionally and first.
            DefaultMetadata?.Invoke(_adapter);

            var handler = DefaultEventRef;
            var compat = DefaultEvent;

            if (handler == null && compat == null)
            {
                return;
            }

            // The ref surface reads the record header without a schema, so it is not gated
            // on one. The compat IEventRecord surface mirrors C++/CLI.
            handler?.Invoke(view);

            if (compat == null)
            {
                return;
            }

            SchemaEntry schema = view.SchemaEntry;

            if (schema.Status != NativeConstants.ERROR_SUCCESS)
            {
                var errorHandler = DefaultError;
                errorHandler?.Invoke(new EventRecordError(
                    ErrorMessages.StatusAndRecordContext(schema.Status, view.ProviderId, view.Id),
                    _adapter));
                return;
            }

            compat(_adapter);
        }

        public void Dispose()
        {
            _scratch.Dispose();
        }
    }

    /// <summary>
    /// Maps the opaque context ETW echoes back on every event to its trace.
    /// </summary>
    /// <remarks>
    /// An index into a static array rather than a GCHandle: resolving the trace is then an
    /// array load instead of a handle dereference, on a path that runs once per event. A
    /// managed reference cannot be stored in the native context field because the GC would
    /// relocate the object out from under it.
    /// </remarks>
    internal static class TraceRegistry
    {
        private static readonly object Gate = new object();
        private static TraceContext?[] _contexts = new TraceContext?[8];

        public static int Register(TraceContext context)
        {
            lock (Gate)
            {
                for (int i = 0; i < _contexts.Length; i++)
                {
                    if (_contexts[i] == null)
                    {
                        Volatile.Write(ref _contexts[i], context);
                        return i;
                    }
                }

                int index = _contexts.Length;

                // Grow into a fresh array and publish it only once fully populated, so a
                // callback thread reading the field concurrently sees either the old array
                // or a complete new one.
                var grown = new TraceContext?[_contexts.Length * 2];
                Array.Copy(_contexts, grown, _contexts.Length);
                grown[index] = context;
                Volatile.Write(ref _contexts, grown);

                return index;
            }
        }

        public static void Unregister(int index)
        {
            lock (Gate)
            {
                TraceContext?[] contexts = _contexts;

                if (index >= 0 && index < contexts.Length)
                {
                    Volatile.Write(ref contexts[index], null);
                }
            }
        }

        /// <summary>
        /// Resolves a context without locking. The array reference is only ever replaced by a
        /// fully populated copy, so a torn read is not possible.
        /// </summary>
        public static TraceContext? Get(int index)
        {
            TraceContext?[] contexts = Volatile.Read(ref _contexts);
            return (uint)index < (uint)contexts.Length ? Volatile.Read(ref contexts[index]) : null;
        }
    }

    /// <summary>
    /// The native entry points ETW calls. Kept static so the same dispatch path is used on
    /// every target framework.
    /// </summary>
    internal static unsafe class TraceCallbacks
    {
#if NET
        public static IntPtr EventRecordCallback
        {
            get { return (IntPtr)(delegate* unmanaged<EVENT_RECORD*, void>)&OnEventRecord; }
        }

        public static IntPtr BufferCallback
        {
            get { return (IntPtr)(delegate* unmanaged<IntPtr, uint>)&OnBuffer; }
        }

        [UnmanagedCallersOnly]
        private static void OnEventRecord(EVENT_RECORD* record)
        {
            Dispatch(record);
        }

        [UnmanagedCallersOnly]
        private static uint OnBuffer(IntPtr logfile)
        {
            CountBuffer(logfile);
            return 1;
        }
#else
        // The parameters are declared as IntPtr rather than typed pointers: EVENT_TRACE_LOGFILE
        // is not blittable, and the CLR refuses to build a thunk for a pointer to a marshalled
        // structure. The pointers are cast back to their real types inside the thunk.
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate void EventRecordCallbackDelegate(IntPtr record);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate uint BufferCallbackDelegate(IntPtr logfile);

        // Held in static fields so the delegates outlive every trace; a collected delegate
        // would leave ETW calling into freed thunk memory.
        private static readonly EventRecordCallbackDelegate EventRecordThunk =
            record => Dispatch((EVENT_RECORD*)record);

        private static readonly BufferCallbackDelegate BufferThunk =
            logfile =>
            {
                CountBuffer(logfile);
                return 1;
            };

        private static readonly IntPtr EventRecordThunkPointer =
            Marshal.GetFunctionPointerForDelegate(EventRecordThunk);

        private static readonly IntPtr BufferThunkPointer =
            Marshal.GetFunctionPointerForDelegate(BufferThunk);

        public static IntPtr EventRecordCallback
        {
            get { return EventRecordThunkPointer; }
        }

        public static IntPtr BufferCallback
        {
            get { return BufferThunkPointer; }
        }
#endif

        internal static Exception? LastException;

        // EVENT_TRACE_LOGFILE is not blittable, so the buffer callback receives it as an
        // opaque pointer. Only the trailing Context field is needed, and its offset is taken
        // from the declared layout rather than hard coded.
        private static readonly int ContextOffset =
            (int)Marshal.OffsetOf(typeof(EVENT_TRACE_LOGFILE), nameof(EVENT_TRACE_LOGFILE.Context));

        private static void CountBuffer(IntPtr logfile)
        {
            try
            {
                if (logfile == IntPtr.Zero)
                {
                    return;
                }

                var index = (int)*(IntPtr*)((byte*)logfile + ContextOffset);
                TraceContext? context = TraceRegistry.Get(index);

                if (context != null)
                {
                    context.BuffersProcessed++;
                }
            }
            catch (Exception ex)
            {
                LastException = ex;
            }
        }

        private static void Dispatch(EVENT_RECORD* record)
        {
            // Nothing may propagate into native code: ETW has no way to handle it and the
            // process would be torn down.
            try
            {
                TraceContext? context = TraceRegistry.Get((int)record->UserContext);
                context?.OnEvent(record);
            }
            catch (Exception ex)
            {
                LastException = ex;
            }
        }
    }
}
