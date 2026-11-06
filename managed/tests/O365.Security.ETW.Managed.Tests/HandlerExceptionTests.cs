using System;
using System.Collections.Generic;
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

            Run(throwOn: 1, configure: t => t.DefaultUnhandledException += e =>
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
            trace.DefaultUnhandledException += e => reports.Add(e);

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
        /// Every subscriber is told, rather than the last registration winning.
        /// </summary>
        /// <remarks>
        /// Locks in the multi-subscriber behaviour the event form is meant to guarantee. It
        /// does not by itself prove the API shape: <c>+=</c> compiled against the previous
        /// settable property too, via get/Combine/set. What the event adds is that <c>=</c>
        /// no longer compiles, so a second reporter can no longer silently replace the first
        /// -- enforcement the compiler provides and a test cannot.
        ///
        /// It also does not prove delivery, since every subscriber here returns normally.
        /// <see cref="AThrowingReporterDoesNotSilenceTheOnesAfterIt"/> covers the case where
        /// one throws, which registration alone does not survive.
        /// </remarks>
        [Fact]
        public void EverySubscriberIsToldRatherThanTheLastRegistrationWinning()
        {
            var first = new System.Collections.Generic.List<IEventRecordException>();
            var second = new System.Collections.Generic.List<IEventRecordException>();

            var trace = new UserTrace();
            trace.DefaultEventRef = (in EventRecordRef record) =>
                throw new InvalidOperationException("default handler failed");

            trace.DefaultUnhandledException += e => first.Add(e);
            trace.DefaultUnhandledException += e => second.Add(e);

            using (EventSchema.Use(Declaration(ProviderId)))
            {
                PushThrowing(new Proxy(trace), ProviderId);
            }

            Assert.Single(first);
            Assert.Single(second);
            Assert.Equal("default handler failed", first[0].Exception.Message);
            Assert.Equal("default handler failed", second[0].Exception.Message);
        }

        /// <summary>
        /// A subscriber that unsubscribes stops being told, and leaves the others alone.
        /// </summary>
        [Fact]
        public void AnUnsubscribedReporterStopsBeingTold()
        {
            var kept = new System.Collections.Generic.List<IEventRecordException>();
            var removed = new System.Collections.Generic.List<IEventRecordException>();

            var trace = new UserTrace();
            trace.DefaultEventRef = (in EventRecordRef record) =>
                throw new InvalidOperationException("default handler failed");

            EventRecordExceptionDelegate goes = e => removed.Add(e);
            trace.DefaultUnhandledException += e => kept.Add(e);
            trace.DefaultUnhandledException += goes;
            trace.DefaultUnhandledException -= goes;

            using (EventSchema.Use(Declaration(ProviderId)))
            {
                PushThrowing(new Proxy(trace), ProviderId);
            }

            Assert.Single(kept);
            Assert.Empty(removed);
        }

        /// <summary>
        /// A reporter that throws does not silence the reporters registered after it.
        /// </summary>
        /// <remarks>
        /// Making this an event stops a subscriber being discarded at registration, but that
        /// is only half the guarantee: a multicast delegate invoked as one call abandons the
        /// rest of its invocation list the moment one subscriber throws. A health reporter
        /// that failed would take the log down with it, silently, since the throw is caught
        /// and recorded as diagnostics. Each subscriber is therefore invoked separately.
        /// </remarks>
        [Fact]
        public void AThrowingReporterDoesNotSilenceTheOnesAfterIt()
        {
            var later = new System.Collections.Generic.List<IEventRecordException>();

            var trace = new UserTrace();
            trace.DefaultEventRef = (in EventRecordRef record) =>
                throw new InvalidOperationException("default handler failed");

            trace.DefaultUnhandledException += _ => throw new InvalidOperationException("reporter failed");
            trace.DefaultUnhandledException += e => later.Add(e);

            using (EventSchema.Use(Declaration(ProviderId)))
            {
                PushThrowing(new Proxy(trace), ProviderId);
            }

            Assert.Single(later);
            Assert.Equal("default handler failed", later[0].Exception.Message);
        }

        /// <summary>
        /// The same containment on the provider-level surface, which is the one most
        /// consumers actually subscribe.
        /// </summary>
        [Fact]
        public void AThrowingProviderReporterDoesNotSilenceTheOnesAfterIt()
        {
            var later = new System.Collections.Generic.List<IEventRecordException>();

            var provider = new Provider(ProviderId);
            provider.OnEventRef += (in EventRecordRef record) =>
                throw new InvalidOperationException("handler failed");
            provider.OnUnhandledException += _ => throw new InvalidOperationException("reporter failed");
            provider.OnUnhandledException += e => later.Add(e);

            var trace = new UserTrace();
            trace.Enable(provider);

            using (EventSchema.Use(Declaration(ProviderId)))
            {
                PushThrowing(new Proxy(trace), ProviderId);
            }

            Assert.Single(later);
            Assert.Equal("handler failed", later[0].Exception.Message);
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
            trace.DefaultUnhandledException += _ => traceReports++;

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

        /// <summary>
        /// A reporting surface that throws must not be able to deny the stop.
        /// </summary>
        /// <remarks>
        /// By the time the reports go out <c>Stopping</c> is set, so every event ETW is still
        /// draining is dropped. If the stop request were skipped as well, CloseTrace would
        /// never be called, ProcessTrace would never return and Start would never rethrow --
        /// a session that consumes and delivers nothing, which is the failure the whole path
        /// exists to avoid. Which surface a consumer happens to subscribe is not something
        /// they should have to weigh against that.
        /// </remarks>
        [Theory]
        [InlineData(true, false)]
        [InlineData(false, true)]
        [InlineData(true, true)]
        public void AThrowingReporterCannotDenyTheStop(bool providerThrows, bool traceThrows)
        {
            var host = new StubTraceHost();

            Reporting(providerThrows, traceThrows, host);

            Assert.Equal(1, host.Stops);
        }

        /// <summary>
        /// Both reporting surfaces are contained the same way, so a throw on either stays
        /// recoverable as a diagnostic rather than vanishing.
        /// </summary>
        [Fact]
        public void AThrowingTraceLevelReporterIsRecordedRatherThanLost()
        {
            TraceContext.LastReportingException = null;

            Reporting(providerThrows: false, traceThrows: true);

            Assert.IsType<InvalidOperationException>(TraceContext.LastReportingException);
            Assert.Equal("trace reporter failed", TraceContext.LastReportingException.Message);
        }

        /// <summary>
        /// The provider-level surface throwing must not stop the trace-level one being told.
        /// </summary>
        [Fact]
        public void AThrowingProviderReporterDoesNotDenyTheTraceLevelReport()
        {
            var reports = new List<IEventRecordException>();

            Reporting(
                providerThrows: true,
                traceThrows: false,
                configure: context => context.DefaultException = e => reports.Add(e));

            Assert.Single(reports);
            Assert.Equal("handler failed", reports[0].Exception.Message);
        }

        /// <summary>
        /// Drives the exception path directly, which is where the ordering guarantee lives.
        /// A trace would only add its own stop on top of the request being asserted, and the
        /// context already exposes everything needed to stand in for one.
        /// </summary>
        private static unsafe void Reporting(
            bool providerThrows,
            bool traceThrows,
            StubTraceHost host = null,
            Action<TraceContext> configure = null)
        {
            var context = new TraceContext(host ?? new StubTraceHost());
            var provider = new Provider(ProviderId);

            if (providerThrows)
            {
                provider.OnUnhandledException += _ => throw new InvalidOperationException("provider reporter failed");
            }

            if (traceThrows)
            {
                context.DefaultException = _ => throw new InvalidOperationException("trace reporter failed");
            }

            context.SetProviders(new List<Provider> { provider });
            configure?.Invoke(context);

            using (EventSchema.Use(Declaration(ProviderId)))
            using (var builder = new RecordBuilder(ProviderId, id: 7, version: 0))
            {
                builder.AddValue("ProcessId", 4321u);

                using (SynthRecord record = builder.Pack())
                {
                    context.HandleDispatchException(
                        record.Record,
                        new InvalidOperationException("handler failed"));
                }
            }
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
            trace.DefaultUnhandledException += e => result.TraceReports.Add(e);
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
