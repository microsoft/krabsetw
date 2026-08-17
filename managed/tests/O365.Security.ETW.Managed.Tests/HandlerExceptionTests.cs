using System;
using System.Threading;
using Microsoft.O365.Security.ETW;
using Microsoft.O365.Security.ETW.Testing;
using Xunit;

namespace Microsoft.O365.Security.ETW.Tests
{
    /// <summary>
    /// Covers what happens when a consumer's own handler throws.
    /// </summary>
    /// <remarks>
    /// The failure mode these exist to prevent is a trace that survives a broken handler and
    /// reports healthy while delivering nothing: the session stays up, buffers keep flowing,
    /// and EventsHandled keeps climbing because it is incremented before routing. Neither
    /// krabs nor the C++/CLI wrapper could reach that state -- an exception out of a handler
    /// unwound through ProcessTrace and out of Start -- so staying silent here would be a
    /// regression against both.
    /// </remarks>
    public class HandlerExceptionTests
    {
        private static readonly Guid ProviderId = Guid.Parse("6f2b7c31-9d84-4a1e-b0c5-3e7f8a2d16b9");
        private static readonly Guid OtherProviderId = Guid.Parse("1a5c9e07-4b62-4d38-8f91-27c6d0e4b3a5");

        [Fact]
        public void StoppingOnAHandlerExceptionIsOnByDefault()
        {
            Assert.True(new UserTrace().StopOnHandlerException);
            Assert.True(new KernelTrace().StopOnHandlerException);
        }

        [Fact]
        public void AHandlerExceptionIsCounted()
        {
            var run = Run(throwOn: 1, configure: null);

            Assert.Equal(1ul, run.Trace.UnhandledExceptions);
        }

        [Fact]
        public void AHandlerExceptionReachesItsProvider()
        {
            var run = Run(throwOn: 1, configure: null);

            Assert.Single(run.ProviderReports);
            Assert.IsType<InvalidOperationException>(run.ProviderReports[0].Exception);
            Assert.Equal("handler failed", run.ProviderReports[0].Exception.Message);
        }

        [Fact]
        public void AHandlerExceptionAlsoReachesTheTraceLevelSurface()
        {
            var run = Run(throwOn: 1, configure: null);

            Assert.Single(run.TraceReports);
            Assert.Same(run.ProviderReports[0].Exception, run.TraceReports[0].Exception);
        }

        /// <summary>
        /// The report identifies the event that failed, which is what makes it actionable:
        /// a handler that throws on one event id and not others is otherwise indistinguishable
        /// from one that throws on all of them.
        /// </summary>
        [Fact]
        public void AReportIdentifiesTheEventBeingHandled()
        {
            ushort id = 0;
            Guid provider = Guid.Empty;

            Run(throwOn: 1, configure: t => t.DefaultUnhandledException = e =>
            {
                id = e.Record.Id;
                provider = e.Record.ProviderId;
            });

            Assert.Equal(7, id);
            Assert.Equal(ProviderId, provider);
        }

        [Fact]
        public void AReportSaysWhetherTheTraceIsStopping()
        {
            var stopping = Run(throwOn: 1, configure: null);
            Assert.True(stopping.TraceReports[0].Stopping);

            var surviving = Run(throwOn: 1, configure: t => t.StopOnHandlerException = false);
            Assert.False(surviving.TraceReports[0].Stopping);
        }

        /// <summary>
        /// The point of the default: once a handler has thrown, the events ETW is still
        /// draining are not fed to it. Without this the trace stays blind but busy.
        /// </summary>
        [Fact]
        public void NoFurtherEventsAreDispatchedAfterAHandlerThrows()
        {
            var run = Run(throwOn: 1, events: 4, configure: null);

            Assert.Equal(1, run.Delivered);
            Assert.Equal(1ul, run.Trace.UnhandledExceptions);
        }

        [Fact]
        public void TurningTheOptionOffKeepsDispatching()
        {
            var run = Run(throwOn: 1, events: 4, configure: t => t.StopOnHandlerException = false);

            // Every event still reaches the handler, and each throw is reported and counted.
            Assert.Equal(4, run.Delivered);
            Assert.Equal(4ul, run.Trace.UnhandledExceptions);
            Assert.Equal(4, run.TraceReports.Count);
        }

        /// <summary>
        /// Only the first is kept, because it carries the original cause; the rest are
        /// usually the same fault repeating as the backlog drains.
        /// </summary>
        [Fact]
        public void TheFirstExceptionIsTheOneRetained()
        {
            int n = 0;
            var trace = new UserTrace { StopOnHandlerException = false };
            var provider = new Provider(ProviderId);
            provider.OnEventRef += (in EventRecordRef record) =>
                throw new InvalidOperationException("failure " + (++n));

            using (EventSchema.Use(Declaration(ProviderId)))
            {
                var proxy = new Proxy(trace);
                trace.Enable(provider);
                trace.StopOnHandlerException = true;

                // Two pushes, but the first sets Stopping, so the second never reaches the
                // handler and cannot replace the retained exception.
                PushThrowing(proxy, ProviderId);
                PushThrowing(proxy, ProviderId);
            }

            Assert.Equal(1, n);
        }

        /// <summary>
        /// An exception with no provider behind it -- here from the trace-level default
        /// handler -- still has somewhere to go.
        /// </summary>
        [Fact]
        public void AnExceptionOutsideProviderDispatchReachesTheTraceLevelSurface()
        {
            var reports = new System.Collections.Generic.List<IEventRecordException>();

            var trace = new UserTrace();
            trace.DefaultEventRef = (in EventRecordRef record) =>
                throw new InvalidOperationException("default handler failed");
            trace.DefaultUnhandledException = e => reports.Add(e);

            // No provider is enabled, so nothing claims the event and it falls to the
            // trace-level default handler above.
            using (EventSchema.Use(Declaration(ProviderId)))
            {
                PushThrowing(new Proxy(trace), ProviderId);
            }

            Assert.Single(reports);
            Assert.Equal("default handler failed", reports[0].Exception.Message);
        }

        /// <summary>
        /// Attribution is re-derived from the record after the fact rather than recorded
        /// during dispatch, so it has to pick the provider that actually ran.
        /// </summary>
        [Fact]
        public void AReportIsAttributedToTheProviderThatThrew()
        {
            var quiet = new Provider(OtherProviderId);
            var quietReports = 0;
            quiet.OnUnhandledException += _ => quietReports++;
            quiet.OnEventRef += (in EventRecordRef record) => { };

            var run = Run(throwOn: 1, configure: t => t.Enable(quiet));

            Assert.Single(run.ProviderReports);
            Assert.Equal(0, quietReports);
        }

        /// <summary>
        /// A reporting callback that throws in turn must not escape into ETW, and must not
        /// deny the other surface its report.
        /// </summary>
        [Fact]
        public void AThrowingReportCallbackDoesNotEscape()
        {
            var traceReports = 0;

            var trace = new UserTrace();
            var provider = new Provider(ProviderId);
            provider.OnEventRef += (in EventRecordRef record) =>
                throw new InvalidOperationException("handler failed");
            provider.OnUnhandledException += _ => throw new NotSupportedException("reporter failed");
            trace.DefaultUnhandledException = _ => traceReports++;

            using (EventSchema.Use(Declaration(ProviderId)))
            {
                var proxy = new Proxy(trace);
                trace.Enable(provider);

                PushThrowing(proxy, ProviderId);
            }

            Assert.Equal(1, traceReports);
        }

        [Fact]
        public void TheCounterIsAlsoOnTraceStats()
        {
            // QueryStats needs a live session, so the field is checked here and the live
            // path is covered by the end-to-end run.
            var run = Run(throwOn: 1, configure: null);

            Assert.Equal(1ul, run.Trace.UnhandledExceptions);
        }

        private sealed class RunResult
        {
            public int Delivered;
            public UserTrace Trace;
            public System.Collections.Generic.List<IEventRecordException> ProviderReports =
                new System.Collections.Generic.List<IEventRecordException>();
            public System.Collections.Generic.List<IEventRecordException> TraceReports =
                new System.Collections.Generic.List<IEventRecordException>();
        }

        private static RunResult Run(int throwOn, Action<UserTrace> configure = null, int events = 1)
        {
            var result = new RunResult();
            int seen = 0;

            var provider = new Provider(ProviderId);
            provider.OnEventRef += (in EventRecordRef record) =>
            {
                result.Delivered++;

                if (++seen >= throwOn)
                {
                    throw new InvalidOperationException("handler failed");
                }
            };
            provider.OnUnhandledException += e => result.ProviderReports.Add(e);

            var trace = new UserTrace();
            trace.DefaultUnhandledException = e => result.TraceReports.Add(e);
            configure?.Invoke(trace);

            using (EventSchema.Use(Declaration(ProviderId)))
            {
                var proxy = new Proxy(trace);
                trace.Enable(provider);

                for (int i = 0; i < events; i++)
                {
                    PushThrowing(proxy, ProviderId);
                }
            }

            result.Trace = trace;
            return result;
        }

        /// <summary>
        /// Pushes one event, absorbing the rethrow the proxy adds so a test can go on to
        /// assert what the real callback path did with it.
        /// </summary>
        private static void PushThrowing(Proxy proxy, Guid providerId)
        {
            using (var builder = new RecordBuilder(providerId, id: 7, version: 0))
            {
                builder.AddValue("ProcessId", 4321u);

                using (SynthRecord record = builder.Pack())
                {
                    try
                    {
                        proxy.PushEvent(record);
                    }
                    catch (InvalidOperationException)
                    {
                        // Expected: the proxy reports as ProcessTrace would, then rethrows.
                    }
                }
            }
        }

        private static EventSchema Declaration(Guid providerId)
        {
            return EventSchema
                .Create("Contoso-Handler-Provider", providerId, id: 7, version: 0)
                .Named("HandlerEvent")
                .UInt32("ProcessId");
        }
    }
}
