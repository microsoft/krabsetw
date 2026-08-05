using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading;
using O365.Security.ETW.Interop;

namespace O365.Security.ETW
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
    /// A real-time ETW session.
    /// </summary>
    public sealed unsafe class UserTrace : IDisposable
    {
        private readonly object _gate = new object();
        private readonly List<Provider> _providers = new List<Provider>();
        private readonly string _name;

        private TraceContext _context;
        private int _contextIndex = -1;

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
        public ulong BuffersProcessed { get; private set; }

        public bool MOFEventProcessingEnabled { get; set; }

        public bool WPPEventProcessingEnabled { get; set; }

        /// <summary>Handles events with no matching provider. Zero-copy path.</summary>
        public EventRecordDelegate DefaultEventSpan
        {
            set { _context.DefaultEventSpan = value; }
        }

        public IEventRecordDelegate DefaultEvent
        {
            set { _context.DefaultEvent = value; }
        }

        public IEventRecordMetadataDelegate DefaultMetadata
        {
            set { _context.DefaultMetadata = value; }
        }

        public EventRecordErrorDelegate DefaultError
        {
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
                    EnableProvider(provider);
                    _context.SetProviders(_providers);
                }
            }
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

                foreach (Provider provider in _providers)
                {
                    EnableProvider(provider);
                }

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
            int status = NativeMethods.ProcessTrace(&handle, 1, IntPtr.Zero, IntPtr.Zero);

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

        private void EnableProvider(Provider provider)
        {
            List<ushort> eventIds = CollectPushdownEventIds(provider);

            var parameters = default(ENABLE_TRACE_PARAMETERS);
            parameters.Version = 2;
            parameters.EnableProperty = provider.TraceFlags;

            Guid id = provider.Id;
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
        }

        private const int EventFilterEventIdHeaderSize = 4;

        /// <summary>
        /// Collects the event ids that can be pushed into ETW for a provider.
        /// </summary>
        /// <remarks>
        /// Only safe when every filter reduces to a bounded id set and the provider itself
        /// has no unconditional handler. If anything on the provider might want an event
        /// outside those ids, filtering in the kernel would silently drop it.
        /// </remarks>
        private static List<ushort> CollectPushdownEventIds(Provider provider)
        {
            if (provider.HasProviderHandlers || provider.Filters.Count == 0)
            {
                return null;
            }

            var ids = new List<ushort>();

            foreach (EventFilter filter in provider.Filters)
            {
                IReadOnlyList<ushort> filterIds = filter.EventIds;
                if (filterIds == null)
                {
                    return null;
                }

                foreach (ushort id in filterIds)
                {
                    if (!ids.Contains(id))
                    {
                        ids.Add(id);
                    }
                }
            }

            if (ids.Count == 0 || ids.Count > NativeConstants.MAX_EVENT_FILTER_EVENT_ID_COUNT)
            {
                return null;
            }

            return ids;
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
