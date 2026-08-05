using System;
using System.Collections.Generic;
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
    public struct TraceStats
    {
        public uint BuffersCount;
        public uint BuffersFree;
        public uint BuffersWritten;
        public uint BuffersLost;
        public ulong EventsTotal;
        public ulong EventsHandled;
        public uint EventsLost;
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
        private readonly string _name;
        private readonly ManualResetEventSlim _processingStopped = new ManualResetEventSlim(true);

        private TraceContext _context;
        private int _contextIndex = -1;
        private Thread _processingThread;

        private ulong _sessionHandle;
        private ulong _traceHandle;
        private IntPtr _loggerName;
        private bool _opened;
        private bool _disposed;
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

        /// <summary>Handles events with no matching provider. Zero-copy path.</summary>
        public EventRecordDelegate DefaultEventSpan
        {
            get { return _context.DefaultEventSpan; }
            set { _context.DefaultEventSpan = value; }
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

                if (_opened)
                {
                    EnableProviders();
                    _context.SetProviders(_providers);
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
        /// Delivers a record to this trace's providers as though ETW had produced it.
        /// Drives <see cref="Testing.Proxy"/>; not part of the consumer API.
        /// </summary>
        internal unsafe void PushEvent(Interop.EVENT_RECORD* record)
        {
            lock (_gate)
            {
                if (!_opened)
                {
                    _context.SetProviders(_providers);
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
                EnableProviders();

                _context.SetProviders(_providers);
                _contextIndex = TraceRegistry.Register(_context);
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

            ulong handle = _traceHandle;

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
            }

            if (status != NativeConstants.ERROR_SUCCESS && status != NativeConstants.ERROR_CANCELLED)
            {
                throw new TraceException("ProcessTrace failed.", status);
            }
        }

        public void Stop()
        {
            lock (_gate)
            {
                if (!_opened)
                {
                    return;
                }

                if (_sessionHandle != 0)
                {
                    ControlSession(NativeConstants.EVENT_TRACE_CONTROL_STOP);
                    _sessionHandle = 0;
                }

                if (_traceHandle != 0)
                {
                    NativeMethods.CloseTrace(_traceHandle);
                    _traceHandle = 0;
                }

                // CloseTrace only requests that processing end; ProcessTrace keeps draining
                // buffered events for a while afterwards. Unregistering the context or
                // freeing the cached schema blobs before it returns would leave the callback
                // thread reading freed memory.
                WaitForProcessingToStop();

                if (_contextIndex >= 0)
                {
                    TraceRegistry.Unregister(_contextIndex);
                    _contextIndex = -1;
                }

                if (_loggerName != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(_loggerName);
                    _loggerName = IntPtr.Zero;
                }

                _opened = false;
            }
        }

        private void WaitForProcessingToStop()
        {
            // Stopping from inside a handler is legal; the processing thread cannot wait for
            // itself, and the callback frames below it still need the context alive.
            if (_processingThread == Thread.CurrentThread)
            {
                return;
            }

            _processingStopped.Wait(TimeSpan.FromSeconds(30));
        }

        public TraceStats QueryStats()
        {
            var stats = default(TraceStats);

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

            stats.BuffersCount = properties->NumberOfBuffers;
            stats.BuffersFree = properties->FreeBuffers;
            stats.BuffersWritten = properties->BuffersWritten;
            stats.BuffersLost = properties->RealTimeBuffersLost;
            stats.EventsLost = properties->EventsLost;
            stats.EventsTotal = _context.EventsTotal;
            stats.EventsHandled = _context.EventsHandled;

            return stats;
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

            // ETW is not documented to copy the logger name, so it stays allocated for as
            // long as the trace handle is open.
            _loggerName = Marshal.StringToHGlobalUni(_name);
            logfile.LoggerName = _loggerName;

            _traceHandle = NativeMethods.OpenTrace(&logfile);

            if (_traceHandle == InvalidTraceHandle)
            {
                int error = Marshal.GetLastWin32Error();

                Marshal.FreeHGlobal(_loggerName);
                _loggerName = IntPtr.Zero;
                TraceRegistry.Unregister(_contextIndex);
                _contextIndex = -1;

                throw new TraceException("OpenTrace failed for session '" + _name + "'.", error);
            }
        }

        private static ulong InvalidTraceHandle
        {
            get { return IntPtr.Size == 8 ? ulong.MaxValue : 0x00000000FFFFFFFFUL; }
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

            foreach (Provider provider in _providers)
            {
                MergedProvider entry = null;

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
            public List<ushort> EventIds = new List<ushort>();

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

                if (!CollectPushdownEventIds(provider, EventIds))
                {
                    _pushdownDeclined = true;
                    EventIds = null;
                }
            }
        }

        private void EnableMerged(MergedProvider provider)
        {
            List<ushort> eventIds = provider.EventIds;

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
                status = NativeMethods.EnableTraceEx2(
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
                    throw new TraceException("EnableTraceEx2(CAPTURE_STATE) failed for provider " + provider.Id + ".", status);
                }
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
                IReadOnlyList<ushort> filterIds = filter.EventIds;
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

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;

            Stop();
            _processingStopped.Dispose();
            _context.Dispose();
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
