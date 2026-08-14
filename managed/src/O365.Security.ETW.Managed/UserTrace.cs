using System;
using System.Collections.Generic;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Threading;
using Microsoft.O365.Security.ETW.Interop;

namespace Microsoft.O365.Security.ETW
{
    /// <summary>Session buffer configuration, passed through to StartTrace.</summary>
    public sealed class EventTraceProperties
    {
        /// <summary>Buffer size in kilobytes.</summary>
        public uint BufferSize { get; set; }

        public uint MinimumBuffers { get; set; }

        public uint MaximumBuffers { get; set; }

        public uint LogFileMode { get; set; }

        /// <summary>Buffer flush interval in seconds.</summary>
        public uint FlushTimer { get; set; }
    }

    /// <summary>Options for <see cref="EventTraceProperties.LogFileMode"/>.</summary>
    public enum LogFileModeFlags : uint
    {
        FLAG_EVENT_TRACE_FILE_MODE_NONE = 0x00000000,
        FLAG_EVENT_TRACE_FILE_MODE_SEQUENTIAL = 0x00000001,
        FLAG_EVENT_TRACE_FILE_MODE_CIRCULAR = 0x00000002,
        FLAG_EVENT_TRACE_FILE_MODE_APPEND = 0x00000004,
        FLAG_EVENT_TRACE_FILE_MODE_NEWFILE = 0x00000008,
        FLAG_EVENT_TRACE_FILE_MODE_PREALLOCATE = 0x00000020,
        FLAG_EVENT_TRACE_NONSTOPPABLE_MODE = 0x00000040,
        FLAG_EVENT_TRACE_SECURE_MODE = 0x00000080,
        FLAG_EVENT_TRACE_REAL_TIME_MODE = 0x00000100,
        FLAG_EVENT_TRACE_DELAY_OPEN_FILE_MODE = 0x00000200,
        FLAG_EVENT_TRACE_BUFFERING_MODE = 0x00000400,
        FLAG_EVENT_TRACE_PRIVATE_LOGGER_MODE = 0x00000800,
        FLAG_EVENT_TRACE_ADD_HEADER_MODE = 0x00001000,
        FLAG_EVENT_TRACE_USE_KBYTES_FOR_SIZE = 0x00002000,
        FLAG_EVENT_TRACE_USE_GLOBAL_SEQUENCE = 0x00004000,
        FLAG_EVENT_TRACE_USE_LOCAL_SEQUENCE = 0x00008000,
        FLAG_EVENT_TRACE_RELOG_MODE = 0x00010000,
        FLAG_EVENT_TRACE_PRIVATE_IN_PROC = 0x00020000,
        FLAG_EVENT_TRACE_MODE_RESERVED = 0x00100000,
        FLAG_EVENT_TRACE_STOP_ON_HYBRID_SHUTDOWN = 0x00400000,
        FLAG_EVENT_TRACE_PERSIST_ON_HYBRID_SHUTDOWN = 0x00800000,
        FLAG_EVENT_TRACE_USE_PAGED_MEMORY = 0x01000000,
        FLAG_EVENT_TRACE_SYSTEM_LOGGER_MODE = 0x02000000,
        FLAG_EVENT_TRACE_COMPRESSED_MODE = 0x04000000,
        FLAG_EVENT_TRACE_INDEPENDENT_SESSION_MODE = 0x08000000,
        FLAG_EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING = 0x10000000,
        FLAG_EVENT_TRACE_ADDTO_TRIAGE_DUMP = 0x80000000
    }

    /// <summary>Counters describing how a session is behaving.</summary>
    /// <remarks>
    /// Readonly so that reading a counter through a field or an <c>in</c> parameter does not
    /// force the compiler to take a defensive copy of the whole struct. The fields stay public
    /// for source compatibility with the C++/CLI value class; only assignment to them is gone,
    /// and nothing outside the library ever produced one.
    /// </remarks>
    public readonly struct TraceStats
    {
        internal TraceStats(
            uint buffersCount,
            uint buffersFree,
            uint buffersWritten,
            uint buffersLost,
            ulong eventsTotal,
            ulong eventsHandled,
            uint eventsLost)
        {
            BuffersCount = buffersCount;
            BuffersFree = buffersFree;
            BuffersWritten = buffersWritten;
            BuffersLost = buffersLost;
            EventsTotal = eventsTotal;
            EventsHandled = eventsHandled;
            EventsLost = eventsLost;
        }

        public readonly uint BuffersCount;
        public readonly uint BuffersFree;
        public readonly uint BuffersWritten;
        public readonly uint BuffersLost;
        public readonly ulong EventsTotal;
        public readonly ulong EventsHandled;
        public readonly uint EventsLost;
    }

    /// <summary>
    /// Represents an instance of an ETW trace session.
    /// </summary>
    public interface ITrace
    {
        /// <summary>Sets the trace properties. Must be called before Open()/Start().</summary>
        void SetTraceProperties(EventTraceProperties properties);

        /// <summary>Starts listening for events from the enabled providers.</summary>
        void Start();

        /// <summary>Stops listening for events.</summary>
        void Stop();

        /// <summary>Gets stats about events handled by this trace.</summary>
        TraceStats QueryStats();
    }

    /// <summary>
    /// User ETW trace specific interface of <see cref="ITrace"/>.
    /// </summary>
    public interface IUserTrace : ITrace
    {
        /// <summary>Enables a provider for the given user trace.</summary>
        void Enable(Provider provider);
    }

    /// <summary>
    /// A real-time ETW session.
    /// </summary>
    public sealed unsafe class UserTrace : IUserTrace, IDisposable
    {
        private readonly object _gate = new object();
        private readonly List<Provider> _providers = new List<Provider>();

        /// <summary>
        /// Providers that asked for rundown events, in the order they were enabled. Held until
        /// <see cref="Start"/> can issue CAPTURE_STATE for them.
        /// </summary>
        private readonly List<Guid> _rundownProviders = new List<Guid>();

        /// <summary>
        /// How long <see cref="Stop"/> waits for ProcessTrace to return. Long enough for a
        /// large backlog to drain, short enough that a hung trace is reported rather than
        /// hanging the caller forever.
        /// </summary>
        private static readonly TimeSpan ProcessingStopTimeout = TimeSpan.FromSeconds(30);

        /// <summary>
        /// Whether <see cref="Start"/> has already issued CAPTURE_STATE for
        /// <see cref="_rundownProviders"/>. A provider enabled after that point has missed the
        /// one issue, so it gets its own.
        /// </summary>
        private bool _rundownIssued;

        private readonly string _name;
        private readonly ManualResetEventSlim _processingStopped = new ManualResetEventSlim(true);

        private TraceContext _context;
        private int _contextIndex = -1;
        /// <remarks>
        /// Written by the processing thread and read by whichever thread calls
        /// <see cref="Stop"/>, so it is volatile: a stale read would make Stop believe it is
        /// the processing thread, skip the wait, and free the context out from under it.
        /// </remarks>
        private volatile Thread? _processingThread;

        private ulong _sessionHandle;
        private TraceHandle? _traceHandle;
        private SafeHGlobalHandle? _loggerName;
        private bool _opened;
        private volatile bool _providersPublished;
        private int _disposed;
        private uint _processTraceMode;

        private EventTraceProperties _properties = new EventTraceProperties
        {
            BufferSize = 256,
            MinimumBuffers = 12,
            MaximumBuffers = 48,
            FlushTimer = 1
        };

        public UserTrace()
            : this("Krabs Managed Trace (" + Guid.NewGuid().ToString("N") + ")")
        {
        }

        public UserTrace(string name)
        {
            _name = name ?? throw new ArgumentNullException(nameof(name));
            _context = new TraceContext();
            _processTraceMode = NativeConstants.PROCESS_TRACE_MODE_REAL_TIME
                | NativeConstants.PROCESS_TRACE_MODE_EVENT_RECORD;
        }

        public string Name
        {
            get { return _name; }
        }

        /// <summary>Number of buffers ProcessTrace has delivered.</summary>
        public ulong BuffersProcessed
        {
            get { return _context.BuffersProcessed; }
        }

        /// <summary>
        /// Routes MOF (classic/WBEM) events to providers. Off by default because it forces a
        /// TDH lookup on every classic event in the session.
        /// </summary>
        public bool MOFEventProcessingEnabled
        {
            get { return _context.MofEventsEnabled; }
            set { _context.MofEventsEnabled = value; }
        }

        /// <summary>Routes WPP events to providers. Off by default, for the same reason.</summary>
        public bool WPPEventProcessingEnabled
        {
            get { return _context.WppEventsEnabled; }
            set { _context.WppEventsEnabled = value; }
        }

        /// <summary>
        /// Handles events with no matching provider, allocating nothing.
        /// </summary>
        /// <inheritdoc cref="Provider.OnEventRef" path="/remarks"/>
        public EventRecordDelegate DefaultEventRef
        {
            get { return _context.DefaultEventRef; }
            set { _context.DefaultEventRef = value; }
        }

        public IEventRecordDelegate DefaultEvent
        {
            get { return _context.DefaultEvent; }
            set { _context.DefaultEvent = value; }
        }

        public IEventRecordMetadataDelegate DefaultMetadata
        {
            get { return _context.DefaultMetadata; }
            set { _context.DefaultMetadata = value; }
        }

        public EventRecordErrorDelegate DefaultError
        {
            get { return _context.DefaultError; }
            set { _context.DefaultError = value; }
        }

        public void SetTraceProperties(EventTraceProperties properties)
        {
            _properties = properties ?? throw new ArgumentNullException(nameof(properties));
        }

        public void Enable(Provider provider)
        {
            if (provider == null) throw new ArgumentNullException(nameof(provider));

            lock (_gate)
            {
                _providers.Add(provider);
                _providersPublished = false;

                if (_opened)
                {
                    EnableProviders();
                    _context.SetProviders(_providers);
                    _providersPublished = true;

                    // Start has already been past its one CAPTURE_STATE, so this provider
                    // would otherwise wait for the next Open/Start cycle for its rundown.
                    if (_rundownIssued && provider.RundownEnabled)
                    {
                        CaptureState(provider.Id);
                    }
                }
            }
        }

        /// <summary>Enables a deprecated raw provider for the given trace.</summary>
        [Obsolete("RawProvider is deprecated. Use Provider with the OnMetadata event instead.")]
        public void Enable(RawProvider provider)
        {
            if (provider == null) throw new ArgumentNullException(nameof(provider));

            Enable(provider.Underlying);
        }

        /// <summary>
        /// The events this trace has seen, routed or not. <see cref="QueryStats"/> is the
        /// consumer-facing form, but it queries the live ETW session, so it cannot be used
        /// against a trace driven by <see cref="Testing.Proxy"/>. Not part of the consumer API.
        /// </summary>
        internal ulong EventsHandledCount
        {
            get { return _context.EventsHandled; }
        }

        /// <summary>
        /// Delivers a record to this trace's providers as though ETW had produced it.
        /// Drives <see cref="Testing.Proxy"/>; not part of the consumer API.
        /// </summary>
        internal unsafe void PushEvent(Interop.EVENT_RECORD* record)
        {
            // Republishing on every push would allocate two arrays per event. Only the
            // first push after an Enable has to do it.
            if (!_providersPublished)
            {
                lock (_gate)
                {
                    if (!_providersPublished)
                    {
                        _context.SetProviders(_providers);
                        _providersPublished = true;
                    }
                }
            }

            _context.OnEvent(record);
        }

        /// <summary>
        /// Creates the session and opens it for consumption, without beginning to process
        /// events. Lets a caller enable providers and know the session exists before
        /// <see cref="Start"/> blocks.
        /// </summary>
        public void Open()
        {
            lock (_gate)
            {
                if (_opened)
                {
                    return;
                }

                StartSession();
                _rundownIssued = false;
                EnableProviders();

                // krabs::trace::open resets the count, so a reopened trace starts from zero.
                _context.EventsHandled = 0;
                _context.BuffersProcessed = 0;

                _context.SetProviders(_providers);
                _providersPublished = true;

                // Reused across Open/Stop cycles: Stop no longer releases it, so registering
                // unconditionally would leak a slot per cycle.
                if (_contextIndex < 0)
                {
                    _contextIndex = TraceRegistry.Register(_context);
                }

                OpenConsumer();

                _opened = true;
            }
        }

        /// <summary>
        /// Processes events until <see cref="Stop"/> is called. Blocks the calling thread,
        /// which becomes the thread every handler runs on.
        /// </summary>
        public void Start()
        {
            Open();

            ulong handle;

            // Read under the lock alongside the rundown, so a Stop racing this cannot null
            // the handle between the two. Read *once*: Stop closes it while ProcessTrace is
            // still running, which is how ETW is told to stop.
            lock (_gate)
            {
                if (_traceHandle == null)
                {
                    // Stopped before processing began. Nothing to drain.
                    return;
                }

                handle = _traceHandle.Value;

                // Immediately before ProcessTrace, per krabs: any later and the rundown
                // events are emitted while nothing is consuming them.
                EnableRundown();
            }

            _processingThread = Thread.CurrentThread;
            _processingStopped.Reset();

            int status;
            try
            {
                status = NativeMethods.ProcessTrace(&handle, 1, IntPtr.Zero, IntPtr.Zero);
            }
            finally
            {
                _processingThread = null;
                _processingStopped.Set();

                // ETW holds the logger name and the callback context for the whole call, and
                // both die with this object. Keeping it reachable here means a trace cannot
                // be finalized while it is still processing, so the finalizer never has to
                // race ProcessTrace.
                GC.KeepAlive(this);
            }

            if (status != NativeConstants.ERROR_SUCCESS && status != NativeConstants.ERROR_CANCELLED)
            {
                throw new TraceException("ProcessTrace failed.", status);
            }
        }

        /// <summary>
        /// Signals the session to stop. Does not wait for processing to finish.
        /// </summary>
        /// <remarks>
        /// This is a signal, not a join, and it matches krabs: its stop is ControlTrace plus
        /// CloseTrace and nothing more. CloseTrace only *asks* that processing end —
        /// ProcessTrace goes on draining buffered events for a while afterwards, running a
        /// handler for each — so a caller that needs "no handler will run again" before
        /// tearing down what its handlers touch has to wait for <see cref="Start"/> to return
        /// on whichever thread it was called.
        ///
        /// Waiting here instead would deadlock against a handler that calls back into its own
        /// trace: the handler would block on <see cref="_gate"/>, so ProcessTrace would never
        /// return, so the wait would never complete.
        ///
        /// Nothing is released here either. The registration and the logger name live until
        /// <see cref="Dispose"/>, which is what makes it safe for this call not to wait: a
        /// still-draining ProcessTrace can keep reading through both.
        /// </remarks>
        public void Stop()
        {
            lock (_gate)
            {
                // Keyed off what exists, not off _opened. Open creates the session before it
                // can fail -- EnableTraceEx2 and OpenTrace both throw -- so a trace can hold a
                // live session while never having finished opening. Returning early there
                // leaks an ETW session, which is machine-wide and outlives the process, and
                // Dispose would then suppress the finalizer that was the last safety net.
                StopSession();
            }
        }

        /// <summary>
        /// Waits for the processing thread to leave ProcessTrace.
        /// </summary>
        /// <returns>
        /// True when processing has stopped and what the callback reaches may be released.
        /// </returns>
        /// <remarks>
        /// Deliberately called outside <see cref="_gate"/>: a handler blocked on that lock
        /// could never let ProcessTrace return, so waiting while holding it would guarantee
        /// the timeout it is trying to detect.
        /// </remarks>
        private bool WaitForProcessingToStop()
        {
            // Disposing from inside a handler is legal, but the processing thread cannot wait
            // for itself and the callback frames below it are still reading through the
            // context. Report failure so the caller leaks rather than freeing underneath them.
            if (_processingThread == Thread.CurrentThread)
            {
                return false;
            }

            return _processingStopped.Wait(ProcessingStopTimeout);
        }

        public TraceStats QueryStats()
        {
            byte* buffer = stackalloc byte[PropertiesBufferSize];
            var properties = (EVENT_TRACE_PROPERTIES*)buffer;
            InitialiseProperties(properties, buffer);

            int status = NativeMethods.ControlTrace(
                _sessionHandle,
                _sessionHandle == 0 ? _name : null,
                properties,
                NativeConstants.EVENT_TRACE_CONTROL_QUERY);

            if (status != NativeConstants.ERROR_SUCCESS)
            {
                throw new TraceException("ControlTrace(QUERY) failed.", status);
            }

            return new TraceStats(
                properties->NumberOfBuffers,
                properties->FreeBuffers,
                properties->BuffersWritten,
                properties->RealTimeBuffersLost,
                _context.EventsHandled + properties->EventsLost,
                _context.EventsHandled,
                properties->EventsLost);
        }

        #region Session setup

        // EVENT_TRACE_PROPERTIES is followed by the logger name, and by a log file name that
        // must be present even for a real-time session.
        private const int MaxNameChars = 1024;
        private static readonly int PropertiesBufferSize =
            sizeof(EVENT_TRACE_PROPERTIES) + (MaxNameChars * 2 * sizeof(char));

        private void InitialiseProperties(EVENT_TRACE_PROPERTIES* properties, byte* buffer)
        {
            for (int i = 0; i < PropertiesBufferSize; i++)
            {
                buffer[i] = 0;
            }

            properties->Wnode.BufferSize = (uint)PropertiesBufferSize;
            properties->Wnode.Flags = NativeConstants.WNODE_FLAG_TRACED_GUID;
            properties->Wnode.ClientContext = 1;
            properties->LogFileMode = NativeConstants.EVENT_TRACE_REAL_TIME_MODE | _properties.LogFileMode;
            properties->BufferSize = _properties.BufferSize;
            properties->MinimumBuffers = _properties.MinimumBuffers;
            properties->MaximumBuffers = _properties.MaximumBuffers;
            properties->FlushTimer = _properties.FlushTimer;
            properties->LoggerNameOffset = (uint)sizeof(EVENT_TRACE_PROPERTIES);
            properties->LogFileNameOffset = 0;
        }

        private void StartSession()
        {
            byte* buffer = stackalloc byte[PropertiesBufferSize];
            var properties = (EVENT_TRACE_PROPERTIES*)buffer;
            InitialiseProperties(properties, buffer);

            int status = NativeMethods.StartTrace(out _sessionHandle, _name, properties);

            if (status == NativeConstants.ERROR_ALREADY_EXISTS)
            {
                // A session survived a previous process. Tear it down and retry rather than
                // silently consuming someone else's configuration.
                ControlExistingSession(NativeConstants.EVENT_TRACE_CONTROL_STOP);
                InitialiseProperties(properties, buffer);
                status = NativeMethods.StartTrace(out _sessionHandle, _name, properties);
            }

            if (status != NativeConstants.ERROR_SUCCESS)
            {
                throw new TraceException("StartTrace failed for session '" + _name + "'.", status);
            }
        }

        private void ControlExistingSession(uint code)
        {
            byte* buffer = stackalloc byte[PropertiesBufferSize];
            var properties = (EVENT_TRACE_PROPERTIES*)buffer;
            InitialiseProperties(properties, buffer);

            NativeMethods.ControlTrace(0, _name, properties, code);
        }

        private void ControlSession(uint code)
        {
            byte* buffer = stackalloc byte[PropertiesBufferSize];
            var properties = (EVENT_TRACE_PROPERTIES*)buffer;
            InitialiseProperties(properties, buffer);

            NativeMethods.ControlTrace(_sessionHandle, null, properties, code);
        }

        private void OpenConsumer()
        {
            var logfile = default(EVENT_TRACE_LOGFILE);
            logfile.ProcessTraceMode = _processTraceMode;
            logfile.EventRecordCallback = TraceCallbacks.EventRecordCallback;
            logfile.BufferCallback = TraceCallbacks.BufferCallback;
            logfile.Context = (IntPtr)_contextIndex;

            // Kept past Stop, because a draining ProcessTrace may still be reading it. The
            // name never changes, so one allocation serves every Open/Stop cycle; its
            // SafeHandle releases it, after this object's finalizer has closed the trace.
            if (_loggerName == null)
            {
                _loggerName = SafeHGlobalHandle.FromUnicodeString(_name);
            }

            logfile.LoggerName = _loggerName.Pointer;

            var opened = new TraceHandle(NativeMethods.OpenTrace(&logfile));

            if (opened.IsInvalid)
            {
                int error = Marshal.GetLastWin32Error();

                // Nothing to release: an invalid SafeHandle never calls ReleaseHandle.
                throw new TraceException("OpenTrace failed for session '" + _name + "'.", error);
            }

            _traceHandle = opened;
        }

        /// <summary>
        /// Enables every provider, merged by GUID.
        /// </summary>
        /// <remarks>
        /// Two Provider objects with the same GUID describe one ETW registration: EnableTraceEx2
        /// replaces the previous settings for a GUID rather than adding to them, so enabling
        /// them separately would leave only the last one's level and keywords in effect. The
        /// flags are OR'd and the pushdown id sets unioned, matching krabs::details::ut.
        /// </remarks>
        private void EnableProviders()
        {
            var merged = new List<MergedProvider>();
            _rundownProviders.Clear();

            foreach (Provider provider in _providers)
            {
                MergedProvider? entry = null;

                for (int i = 0; i < merged.Count; i++)
                {
                    if (merged[i].Id == provider.Id)
                    {
                        entry = merged[i];
                        break;
                    }
                }

                if (entry == null)
                {
                    entry = new MergedProvider(provider.Id);
                    merged.Add(entry);
                }

                entry.Add(provider);
            }

            foreach (MergedProvider entry in merged)
            {
                EnableMerged(entry);
            }
        }

        private sealed class MergedProvider
        {
            public readonly Guid Id;
            public byte Level;
            public ulong Any;
            public ulong All;
            public uint TraceFlags;
            public bool Rundown;

            /// <summary>Null once any contributing provider declines pushdown.</summary>
            public List<ushort>? EventIds = new List<ushort>();

            private bool _pushdownDeclined;

            public MergedProvider(Guid id)
            {
                Id = id;
            }

            public void Add(Provider provider)
            {
                Level |= provider.Level;
                Any |= provider.Any;
                All |= provider.All;
                TraceFlags |= (uint)provider.TraceFlags;
                Rundown |= provider.RundownEnabled;

                if (_pushdownDeclined)
                {
                    return;
                }

                if (!CollectPushdownEventIds(provider, EventIds!))
                {
                    _pushdownDeclined = true;
                    EventIds = null;
                }
            }
        }

        private void EnableMerged(MergedProvider provider)
        {
            List<ushort>? eventIds = provider.EventIds;

            if (eventIds != null
                && (eventIds.Count == 0 || eventIds.Count > NativeConstants.MAX_EVENT_FILTER_EVENT_ID_COUNT))
            {
                eventIds = null;
            }

            var parameters = default(ENABLE_TRACE_PARAMETERS);
            parameters.Version = 2;
            parameters.EnableProperty = provider.TraceFlags;

            Guid id = provider.Id;
            parameters.SourceId = id;

            int status;

            if (eventIds == null)
            {
                status = NativeMethods.EnableTraceEx2(
                    _sessionHandle,
                    &id,
                    NativeConstants.EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                    provider.Level,
                    provider.Any,
                    provider.All,
                    0,
                    &parameters);
            }
            else
            {
                // EVENT_FILTER_EVENT_ID is a header followed by a variable-length id array.
                int size = EventFilterEventIdHeaderSize + (eventIds.Count * sizeof(ushort));
                byte* filter = stackalloc byte[size];

                filter[0] = 1; // FilterIn
                filter[1] = 0; // Reserved
                *(ushort*)(filter + 2) = (ushort)eventIds.Count;

                var events = (ushort*)(filter + EventFilterEventIdHeaderSize);
                for (int i = 0; i < eventIds.Count; i++)
                {
                    events[i] = eventIds[i];
                }

                var descriptor = default(EVENT_FILTER_DESCRIPTOR);
                descriptor.Ptr = (ulong)filter;
                descriptor.Size = (uint)size;
                descriptor.Type = NativeConstants.EVENT_FILTER_TYPE_EVENT_ID;

                parameters.EnableFilterDesc = (IntPtr)(&descriptor);
                parameters.FilterDescCount = 1;

                status = NativeMethods.EnableTraceEx2(
                    _sessionHandle,
                    &id,
                    NativeConstants.EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                    provider.Level,
                    provider.Any,
                    provider.All,
                    0,
                    &parameters);
            }

            if (status != NativeConstants.ERROR_SUCCESS)
            {
                throw new TraceException("EnableTraceEx2 failed for provider " + provider.Id + ".", status);
            }

            if (provider.Rundown)
            {
                _rundownProviders.Add(provider.Id);
            }
        }

        /// <summary>
        /// Asks each provider that opted in to log its state, immediately before ProcessTrace.
        /// Port of krabs::details::ut::enable_rundown.
        /// </summary>
        /// <remarks>
        /// The timing is load-bearing, and krabs says so: CAPTURE_STATE has to be issued very
        /// shortly before ProcessTrace or the rundown events are not generated. Issuing it
        /// from <see cref="Open"/> instead would put an unbounded gap in front of it, because
        /// <see cref="Open"/> and <see cref="Start"/> are separate public calls.
        /// </remarks>
        private void EnableRundown()
        {
            for (int i = 0; i < _rundownProviders.Count; i++)
            {
                CaptureState(_rundownProviders[i]);
            }

            _rundownIssued = true;
        }

        /// <summary>Asks one provider to log its current state.</summary>
        private void CaptureState(Guid provider)
        {
            Guid id = provider;

            int status = NativeMethods.EnableTraceEx2(
                _sessionHandle,
                &id,
                NativeConstants.EVENT_CONTROL_CODE_CAPTURE_STATE,
                0,
                0,
                0,
                0,
                null);

            if (status != NativeConstants.ERROR_SUCCESS)
            {
                throw new TraceException("EnableTraceEx2(CAPTURE_STATE) failed for provider " + id + ".", status);
            }
        }

        private const int EventFilterEventIdHeaderSize = 4;

        /// <summary>
        /// Adds a provider's pushdown-eligible event ids to <paramref name="ids"/>.
        /// </summary>
        /// <returns>
        /// False when the provider is not eligible, in which case nothing may be pushed into
        /// ETW for its GUID.
        /// </returns>
        /// <remarks>
        /// Native krabs unions whatever ids its filters happen to declare and pushes them
        /// regardless, which silently starves any filter or provider callback that wanted a
        /// different event. Declining pushdown for the whole GUID is the conservative
        /// equivalent: it can only ever cost throughput, never correctness.
        /// </remarks>
        private static bool CollectPushdownEventIds(Provider provider, List<ushort> ids)
        {
            if (provider.HasProviderHandlers || provider.Filters.Count == 0)
            {
                return false;
            }

            foreach (EventFilter filter in provider.Filters)
            {
                IReadOnlyList<ushort>? filterIds = filter.EventIds;
                if (filterIds == null)
                {
                    return false;
                }

                foreach (ushort id in filterIds)
                {
                    if (!ids.Contains(id))
                    {
                        ids.Add(id);
                    }
                }
            }

            return true;
        }

        #endregion

        /// <summary>
        /// Stops the trace and releases what its callback reaches.
        /// </summary>
        /// <remarks>
        /// This is where the wait lives, because this is the call that frees the registration
        /// and the logger name. It is also the one call a handler cannot make on its own
        /// trace without the caller having already given up ownership, so waiting here cannot
        /// deadlock against <see cref="Enable(Provider)"/> the way waiting inside
        /// <see cref="Stop"/> did.
        ///
        /// A wait that expires means the processing thread is still inside ProcessTrace.
        /// Nothing is released in that case -- freeing memory it can still reach would turn a
        /// wedged trace into an access violation -- and no exception is raised, because a
        /// caller disposing in a finally block cannot do anything useful with one and would
        /// lose whatever exception it was already unwinding.
        /// </remarks>
        public void Dispose()
        {
            // Interlocked so two threads racing Dispose cannot both run the teardown.
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
            {
                return;
            }

            Stop();

            if (!WaitForProcessingToStop())
            {
                return;
            }

            lock (_gate)
            {
                ReleaseUnmanaged();
            }

            _loggerName?.Dispose();
            _processingStopped.Dispose();
            _context.Dispose();

            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Stops the session if the trace was abandoned without being disposed.
        /// </summary>
        /// <remarks>
        /// Stops the ETW session and closes the consumer handle, and does nothing else. Both
        /// are native calls that take no lock, which matters: a finalizer that blocks on a
        /// lock another thread happens to hold stalls every other finalizer in the process,
        /// including the critical ones that free native memory.
        ///
        /// The callback registration is deliberately *not* released here. It is a weak
        /// reference, so its slot is reclaimed by the next registration that needs one, and
        /// unregistering would mean taking the registry's lock from a finalizer.
        ///
        /// Reaching here means nothing references the trace, and <see cref="Start"/> keeps it
        /// reachable across ProcessTrace, so processing cannot still be running.
        /// </remarks>
        ~UserTrace()
        {
            StopSession();
        }

        /// <summary>
        /// Stops the ETW session and closes the consumer handle. Native calls only, so it is
        /// safe from a finalizer.
        /// </summary>
        private void StopSession()
        {
            if (_sessionHandle != 0)
            {
                ControlSession(NativeConstants.EVENT_TRACE_CONTROL_STOP);
                _sessionHandle = 0;
            }

            // Disposing the handle is what issues CloseTrace, and doing it while ProcessTrace
            // is running is how ETW is told to stop.
            _traceHandle?.Dispose();
            _traceHandle = null;

            _opened = false;
        }

        /// <summary>
        /// Releases the registration. The logger name is a <see cref="SafeHGlobalHandle"/>
        /// and releases itself, which is what keeps its critical finalizer running *after*
        /// this object's ordinary one has closed the trace handle ETW reads it through.
        /// </summary>
        private void ReleaseUnmanaged()
        {
            if (_contextIndex >= 0)
            {
                TraceRegistry.Unregister(_contextIndex, _context);
                _contextIndex = -1;
            }
        }
    }

    /// <summary>
    /// A failure returned by an ETW API, carrying the Win32 status.
    /// </summary>
    public sealed class TraceException : Exception
    {
        public TraceException(string message, int status)
            : base(message + " Status: " + status + ".")
        {
            Status = status;
        }

        public int Status { get; }
    }
}
