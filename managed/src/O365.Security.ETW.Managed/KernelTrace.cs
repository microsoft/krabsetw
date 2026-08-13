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

        /// <remarks>
        /// Written by the processing thread and read by whichever thread calls
        /// <see cref="Dispose"/>, so it is volatile: a stale read would make Dispose believe
        /// it is the processing thread and skip the wait that protects the context.
        /// </remarks>
        private volatile Thread? _processingThread;

        /// <summary>
        /// How long <see cref="Dispose"/> waits for ProcessTrace to return before giving up
        /// and leaving the registration allocated.
        /// </summary>
        private static readonly TimeSpan ProcessingStopTimeout = TimeSpan.FromSeconds(30);

        private ulong _sessionHandle;
        private TraceHandle? _traceHandle;
        private SafeHGlobalHandle? _loggerName;
        private bool _opened;
        private volatile bool _providersPublished;
        private int _disposed;

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

        /// <summary>Allocation-free counterpart to <see cref="DefaultEvent"/>.</summary>
        /// <inheritdoc cref="Provider.OnEventRef" path="/remarks"/>
        public EventRecordDelegate DefaultEventRef
        {
            get { return _context.DefaultEventRef; }
            set { _context.DefaultEventRef = value; }
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

        public void Start()
        {
            Open();

            ulong handle;

            // Read under the lock, so a Stop racing this cannot null the handle first.
            lock (_gate)
            {
                if (_traceHandle == null)
                {
                    return;
                }

                handle = _traceHandle.Value;
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

                // Keeps the trace reachable across ProcessTrace, so it cannot be finalized
                // while ETW still holds its logger name and callback context.
                GC.KeepAlive(this);
            }

            if (status != NativeConstants.ERROR_SUCCESS && status != NativeConstants.ERROR_CANCELLED)
            {
                throw new TraceException("ProcessTrace failed.", status);
            }
        }

        /// <summary>
        /// Signals the session to stop. Does not wait for processing to finish, and does not
        /// release anything the callback thread can still reach; see
        /// <see cref="UserTrace.Stop"/> for why.
        /// </summary>
        public void Stop()
        {
            lock (_gate)
            {
                // Keyed off what exists rather than off _opened; see UserTrace.Stop.
                StopSession();
            }
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

        private void ReleaseUnmanaged()
        {
            if (_contextIndex >= 0)
            {
                TraceRegistry.Unregister(_contextIndex, _context);
                _contextIndex = -1;
            }
        }

        /// <summary>
        /// Waits for the processing thread to leave ProcessTrace.
        /// </summary>
        /// <returns>
        /// True when processing has stopped and what the callback reaches may be released.
        /// </returns>
        /// <remarks>
        /// Called outside <see cref="_gate"/>: a handler blocked on that lock could never let
        /// ProcessTrace return, so waiting while holding it would guarantee the timeout it is
        /// meant to detect.
        /// </remarks>
        private bool WaitForProcessingToStop()
        {
            // Disposing from inside a handler is legal, but the processing thread cannot wait
            // for itself and the frames below it are still reading through the context.
            // Report failure so the caller leaks rather than freeing underneath them.
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
                _context.EventsTotal,
                _context.EventsHandled,
                properties->EventsLost);
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

            // Kept past Stop, because a draining ProcessTrace may still be reading it. Its
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

                throw new TraceException("OpenTrace failed for session '" + _name + "'.", error);
            }

            _traceHandle = opened;
        }

        #endregion

        /// <summary>
        /// Stops the trace and releases what its callback reaches.
        /// </summary>
        /// <remarks>
        /// The wait lives here because this is the call that frees the registration and the
        /// logger name. See <see cref="UserTrace.Dispose"/>.
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

            _context.Dispose();
            _processingStopped.Dispose();
            _loggerName?.Dispose();

            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Stops the session if the trace was abandoned without being disposed. Takes no lock
        /// and releases nothing else; see <see cref="UserTrace"/>'s finalizer for why.
        /// </summary>
        ~KernelTrace()
        {
            StopSession();
        }
    }
}
