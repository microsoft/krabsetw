using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading;
using Microsoft.O365.Security.ETW.Interop;

namespace Microsoft.O365.Security.ETW
{
    /// <summary>
    /// Kernel ETW trace specific interface of <see cref="ITrace"/>.
    /// </summary>
    public interface IKernelTrace : ITrace
    {
        /// <summary>Enables a provider for the given kernel trace.</summary>
        void Enable(KernelProvider provider);
    }

    /// <summary>
    /// A real-time NT kernel logger session.
    /// </summary>
    /// <remarks>
    /// Windows 8 is assumed throughout: the pre-Win8 rules (one machine-wide session forced to
    /// the name "NT Kernel Logger", keyed on SystemTraceControlGuid) are not reproduced,
    /// because no framework this library targets runs there.
    /// </remarks>
    public sealed unsafe class KernelTrace : IKernelTrace, IDisposable
    {
        private readonly object _gate = new object();
        private readonly List<KernelProvider> _providers = new List<KernelProvider>();
        private readonly string _name;
        private readonly ManualResetEventSlim _processingStopped = new ManualResetEventSlim(true);

        private readonly TraceContext _context;
        private int _contextIndex = -1;
        private Thread _processingThread;

        private ulong _sessionHandle;
        private ulong _traceHandle;
        private IntPtr _loggerName;
        private bool _opened;
        private volatile bool _providersPublished;
        private bool _disposed;

        private EventTraceProperties _properties = new EventTraceProperties
        {
            BufferSize = 256,
            MinimumBuffers = 12,
            MaximumBuffers = 48,
            FlushTimer = 1
        };

        public KernelTrace()
            : this("Krabs Managed Kernel Trace (" + Guid.NewGuid().ToString("N") + ")")
        {
        }

        public KernelTrace(string name)
        {
            _name = name ?? throw new ArgumentNullException(nameof(name));
            _context = new TraceContext();
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

        /// <summary>Fired for an event that has no corresponding provider.</summary>
        public IEventRecordMetadataDelegate DefaultMetadata
        {
            get { return _context.DefaultMetadata; }
            set { _context.DefaultMetadata = value; }
        }

        /// <summary>Fired for an event that has no corresponding provider.</summary>
        public IEventRecordDelegate DefaultEvent
        {
            get { return _context.DefaultEvent; }
            set { _context.DefaultEvent = value; }
        }

        /// <summary>Zero-allocation counterpart to <see cref="DefaultEvent"/>.</summary>
        public EventRecordDelegate DefaultEventSpan
        {
            get { return _context.DefaultEventSpan; }
            set { _context.DefaultEventSpan = value; }
        }

        /// <summary>Fired when <see cref="DefaultEvent"/> could not be raised.</summary>
        public EventRecordErrorDelegate DefaultError
        {
            get { return _context.DefaultError; }
            set { _context.DefaultError = value; }
        }

        [Obsolete("This method is deprecated. Use the DefaultMetadata/DefaultEvent/DefaultError event instead.")]
        public void SetDefaultEventCallback(IEventRecordDelegate callback)
        {
            DefaultEvent = callback;
        }

        public void Enable(KernelProvider provider)
        {
            if (provider == null) throw new ArgumentNullException(nameof(provider));

            lock (_gate)
            {
                if (_opened)
                {
                    // The kernel logger's provider set lives in EnableFlags, which is fixed
                    // when the session starts, so a late Enable would silently do nothing.
                    throw new InvalidOperationException(
                        "Kernel providers must be enabled before the trace is opened.");
                }

                _providers.Add(provider);
                _providersPublished = false;
            }
        }

        public void SetTraceProperties(EventTraceProperties properties)
        {
            _properties = properties ?? throw new ArgumentNullException(nameof(properties));
        }

        /// <summary>
        /// Delivers a record to this trace's providers as though ETW had produced it.
        /// Drives <see cref="Testing.Proxy"/>; not part of the consumer API.
        /// </summary>
        internal void PushEvent(EVENT_RECORD* record)
        {
            // Republishing on every push would allocate two arrays per event. Only the
            // first push after an Enable has to do it.
            if (!_providersPublished)
            {
                lock (_gate)
                {
                    if (!_providersPublished)
                    {
                        _context.SetKernelProviders(_providers);
                        _providersPublished = true;
                    }
                }
            }

            _context.OnEvent(record);
        }

        public void Open()
        {
            lock (_gate)
            {
                if (_opened)
                {
                    return;
                }

                StartSession();
                EnableGroupMasks();

                _context.SetKernelProviders(_providers);
                _providersPublished = true;
                _contextIndex = TraceRegistry.Register(_context);
                OpenConsumer();

                _opened = true;
            }
        }

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

        private const int MaxNameChars = 1024;
        private static readonly int PropertiesBufferSize =
            sizeof(EVENT_TRACE_PROPERTIES) + (MaxNameChars * 2 * sizeof(char));

        private uint EnableFlags
        {
            get
            {
                uint flags = 0;

                for (int i = 0; i < _providers.Count; i++)
                {
                    flags |= _providers[i].Flags;
                }

                return flags;
            }
        }

        private void InitialiseProperties(EVENT_TRACE_PROPERTIES* properties, byte* buffer)
        {
            for (int i = 0; i < PropertiesBufferSize; i++)
            {
                buffer[i] = 0;
            }

            properties->Wnode.BufferSize = (uint)PropertiesBufferSize;
            properties->Wnode.Flags = NativeConstants.WNODE_FLAG_TRACED_GUID;
            properties->Wnode.ClientContext = 1;
            properties->Wnode.Guid = Guid.NewGuid();
            properties->LogFileMode = NativeConstants.EVENT_TRACE_REAL_TIME_MODE
                | NativeConstants.EVENT_TRACE_SYSTEM_LOGGER_MODE
                | _properties.LogFileMode;
            properties->EnableFlags = EnableFlags;
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
                ControlExistingSession(NativeConstants.EVENT_TRACE_CONTROL_STOP);
                InitialiseProperties(properties, buffer);
                status = NativeMethods.StartTrace(out _sessionHandle, _name, properties);
            }

            if (status != NativeConstants.ERROR_SUCCESS)
            {
                throw new TraceException("StartTrace failed for session '" + _name + "'.", status);
            }
        }

        /// <summary>
        /// Applies the PERFINFO group masks for providers that have no EVENT_TRACE_FLAG_ bit.
        /// Port of krabs::details::kt::enable_providers.
        /// </summary>
        private void EnableGroupMasks()
        {
            bool anyMask = false;

            for (int i = 0; i < _providers.Count; i++)
            {
                if (_providers[i].GroupMask != 0)
                {
                    anyMask = true;
                    break;
                }
            }

            if (!anyMask)
            {
                return;
            }

            var info = default(EVENT_TRACE_GROUPMASK_INFORMATION);
            info.EventTraceInformationClass = NativeConstants.EventTraceGroupMaskInformation;
            info.TraceHandle = _sessionHandle;

            // Read the masks the EnableFlags above already turned on, so OR-ing ours in does
            // not switch those providers back off.
            int status = NativeMethods.NtQuerySystemInformation(
                NativeConstants.SystemPerformanceTraceInformation,
                &info,
                (uint)sizeof(EVENT_TRACE_GROUPMASK_INFORMATION),
                null);

            if (status < 0)
            {
                throw new TraceException("NtQuerySystemInformation(group masks) failed.", status);
            }

            for (int i = 0; i < _providers.Count; i++)
            {
                uint group = _providers[i].GroupMask;

                if (group == 0)
                {
                    continue;
                }

                // PERFINFO_OR_GROUP_WITH_GROUPMASK: the top three bits select the mask word.
                info.Masks[(group & 0xE0000000u) >> 29] |= group & 0x1FFFFFFFu;
            }

            status = NativeMethods.NtSetSystemInformation(
                NativeConstants.SystemPerformanceTraceInformation,
                &info,
                (uint)sizeof(EVENT_TRACE_GROUPMASK_INFORMATION));

            if (status < 0)
            {
                throw new TraceException("NtSetSystemInformation(group masks) failed.", status);
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
            logfile.ProcessTraceMode = NativeConstants.PROCESS_TRACE_MODE_REAL_TIME
                | NativeConstants.PROCESS_TRACE_MODE_EVENT_RECORD;
            logfile.EventRecordCallback = TraceCallbacks.EventRecordCallback;
            logfile.BufferCallback = TraceCallbacks.BufferCallback;
            logfile.Context = (IntPtr)_contextIndex;

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
            _processingStopped.Dispose();
        }
    }
}
