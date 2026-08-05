using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using O365.Security.ETW.Interop;
using O365.Security.ETW.Schema;

namespace O365.Security.ETW
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

        public ulong EventsTotal;
        public ulong EventsHandled;

        public EventRecordDelegate DefaultEventSpan;
        public IEventRecordDelegate DefaultEvent;
        public IEventRecordMetadataDelegate DefaultMetadata;
        public EventRecordErrorDelegate DefaultError;

        public void SetProviders(List<Provider> providers)
        {
            _providers = providers.ToArray();
            _providerIds = new Guid[_providers.Length];

            for (int i = 0; i < _providers.Length; i++)
            {
                _providerIds[i] = _providers[i].Id;
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
                Guid providerId = record->EventHeader.ProviderId;

                bool matched = false;
                for (int i = 0; i < _providerIds.Length; i++)
                {
                    if (_providerIds[i] != providerId)
                    {
                        continue;
                    }

                    matched = true;
                    _providers[i].Dispatch(view, _adapter);
                }

                if (matched)
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

        private void DispatchDefault(in EventRecordRef view)
        {
            var span = DefaultEventSpan;
            var compat = DefaultEvent;
            var metadata = DefaultMetadata;

            if (span == null && compat == null && metadata == null)
            {
                return;
            }

            try
            {
                if (span != null || compat != null)
                {
                    span?.Invoke(view);
                    compat?.Invoke(_adapter);
                }
                else
                {
                    metadata(_adapter);
                }
            }
            catch (Exception ex)
            {
                var handler = DefaultError;
                if (handler == null)
                {
                    throw;
                }

                handler(new EventRecordError(ex.Message, _adapter));
            }
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
        private static TraceContext[] _contexts = new TraceContext[8];

        public static int Register(TraceContext context)
        {
            lock (Gate)
            {
                for (int i = 0; i < _contexts.Length; i++)
                {
                    if (_contexts[i] == null)
                    {
                        _contexts[i] = context;
                        return i;
                    }
                }

                int index = _contexts.Length;
                Array.Resize(ref _contexts, _contexts.Length * 2);
                _contexts[index] = context;
                return index;
            }
        }

        public static void Unregister(int index)
        {
            lock (Gate)
            {
                if (index >= 0 && index < _contexts.Length)
                {
                    _contexts[index] = null;
                }
            }
        }

        /// <summary>
        /// Resolves a context without locking. Safe because the array reference is only ever
        /// replaced by a fully populated copy, and a trace is unregistered only after
        /// ProcessTrace has returned.
        /// </summary>
        public static TraceContext Get(int index)
        {
            TraceContext[] contexts = _contexts;
            return (uint)index < (uint)contexts.Length ? contexts[index] : null;
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
            get { return (IntPtr)(delegate* unmanaged<EVENT_TRACE_LOGFILE*, uint>)&OnBuffer; }
        }

        [UnmanagedCallersOnly]
        private static void OnEventRecord(EVENT_RECORD* record)
        {
            Dispatch(record);
        }

        [UnmanagedCallersOnly]
        private static uint OnBuffer(EVENT_TRACE_LOGFILE* logfile)
        {
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

        private static readonly BufferCallbackDelegate BufferThunk = _ => 1;

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

        internal static Exception LastException;

        private static void Dispatch(EVENT_RECORD* record)
        {
            // Nothing may propagate into native code: ETW has no way to handle it and the
            // process would be torn down.
            try
            {
                TraceContext context = TraceRegistry.Get((int)record->UserContext);
                context?.OnEvent(record);
            }
            catch (Exception ex)
            {
                LastException = ex;
            }
        }
    }
}
