using System;
using Microsoft.O365.Security.ETW.Interop;
using Microsoft.O365.Security.ETW.Schema;

namespace Microsoft.O365.Security.ETW.Testing
{
    /// <summary>
    /// Serves as a stand-in for a trace, so client code can be tested against hand-built
    /// events without an ETW session. Port of krabs::testing::trace_proxy and
    /// krabs::testing::event_filter_proxy.
    /// </summary>
    public sealed unsafe class Proxy : IDisposable
    {
        private readonly UserTrace? _userTrace;
        private readonly KernelTrace? _kernelTrace;
        private readonly EventFilter? _filter;

        private EventScratch? _scratch;
        private EventRecordAdapter? _adapter;

        /// <summary>Constructs a proxy for the given user trace.</summary>
        public Proxy(UserTrace trace)
        {
            _userTrace = trace ?? throw new ArgumentNullException(nameof(trace));
        }

        /// <summary>Constructs a proxy for the given kernel trace.</summary>
        public Proxy(KernelTrace trace)
        {
            _kernelTrace = trace ?? throw new ArgumentNullException(nameof(trace));
        }

        /// <summary>Constructs a proxy for an event filter.</summary>
        public Proxy(EventFilter filter)
        {
            _filter = filter ?? throw new ArgumentNullException(nameof(filter));
        }

        /// <summary>
        /// Pushes an event through the proxied trace or filter, exactly as ProcessTrace would.
        /// </summary>
        /// <remarks>
        /// The record is kept alive across dispatch. Everything downstream reads through a
        /// raw pointer taken from it, and once that pointer has been read the caller's
        /// <c>PushEvent(builder.Pack())</c> holds no other reference, so a collection landing
        /// inside a handler would otherwise run the record's finalizer and free the payload
        /// while it is being read.
        /// </remarks>
        public void PushEvent(SynthRecord record)
        {
            if (record == null)
            {
                throw new ArgumentNullException(nameof(record));
            }

            try
            {
                if (_userTrace != null)
                {
                    try
                    {
                        _userTrace.PushEvent(record.Record);
                    }
                    catch (Exception ex)
                    {
                        // Exactly what TraceCallbacks.Dispatch does when a handler throws:
                        // count it, report it to the provider and trace surfaces, stop the
                        // trace if configured to, and invalidate the adapter. Doing less
                        // would make this proxy an unfaithful stand-in for ProcessTrace on
                        // the one path where faithfulness matters most.
                        _userTrace.HandleDispatchException(record.Record, ex);

                        // Then rethrow, which the real callback cannot do -- there is native
                        // code above it. A test whose handler threw unintentionally sees the
                        // failure instead of a silently green run.
                        throw;
                    }

                    return;
                }

                if (_kernelTrace != null)
                {
                    try
                    {
                        _kernelTrace.PushEvent(record.Record);
                    }
                    catch (Exception ex)
                    {
                        _kernelTrace.HandleDispatchException(record.Record, ex);
                        throw;
                    }

                    return;
                }

                // A filter is normally driven by its owning trace's scratch and adapter.
                // Standing in for that trace means supplying our own, reused across pushes for
                // the same reason the trace reuses its own.
                if (_scratch == null)
                {
                    _scratch = new EventScratch();
                    _adapter = new EventRecordAdapter();
                }

                EVENT_RECORD* raw = record.Record;

                _scratch!.Begin(raw);
                _adapter!.Begin(raw, _scratch);

                try
                {
                    _filter!.Dispatch(new EventRecordRef(raw, _scratch), _adapter);
                }
                finally
                {
                    _adapter!.End();
                }
            }
            finally
            {
                GC.KeepAlive(record);
            }
        }

        public void Dispose()
        {
            _scratch?.Dispose();
            _scratch = null;
            _adapter = null;
        }
    }
}
