using System;
using Microsoft.O365.Security.ETW.Testing;
using Xunit;

namespace Microsoft.O365.Security.ETW.Tests
{
    /// <summary>
    /// Covers trace-level routing and default dispatch behaviours that are easiest to reach
    /// with synthetic records.
    /// </summary>
    public class TraceContextRoutingCoverageTests
    {
        private static readonly Guid ProviderId = Guid.Parse("d028de6e-0ec2-4d2f-bfe2-24c52ccfbd57");

        [Fact]
        public void UnclaimedEventDispatchesMetadataThenRefThenCompatWhenSchemaResolves()
        {
            string order = string.Empty;
            ushort seenId = 0;
            uint seenValue = 0;

            using (var trace = new UserTrace())
            {
                trace.DefaultMetadata = record => order += "m";
                trace.DefaultEventRef = (in EventRecordRef record) =>
                {
                    order += "r";
                    seenId = record.Id;
                };
                trace.DefaultEvent = record =>
                {
                    order += "c";
                    seenValue = record.GetUInt32("Value", 0);
                };

                using (EventSchema.Use(Declaration()))
                using (SynthRecord record = BuildRecord())
                using (var proxy = new Proxy(trace))
                {
                    proxy.PushEvent(record);
                }

                Assert.Equal("mrc", order);
                Assert.Equal(21, seenId);
                Assert.Equal(42u, seenValue);
                Assert.Equal(1UL, trace.EventsHandledCount);
            }
        }

        [Fact]
        public void DefaultCompatHandlerIsSkippedWhenSchemaCannotResolve()
        {
            int metadata = 0;
            int refs = 0;
            int compat = 0;
            string error = null;

            using (var trace = new UserTrace())
            {
                trace.DefaultMetadata = record => metadata++;
                trace.DefaultEventRef = (in EventRecordRef record) => refs++;
                trace.DefaultEvent = record => compat++;
                trace.DefaultError = e => error = e.Message;

                using (SynthRecord record = BuildRecordWithoutDeclaredSchema())
                using (var proxy = new Proxy(trace))
                {
                    proxy.PushEvent(record);
                }

                Assert.Equal(1, metadata);
                Assert.Equal(1, refs);
                Assert.Equal(0, compat);
                Assert.NotNull(error);
                Assert.Contains("event_id=21", error);
            }
        }

        [Fact]
        public void ProviderHandlerExceptionIsReportedToProviderThenTrace()
        {
            var thrown = new InvalidOperationException("handler failed");
            string order = string.Empty;
            IEventRecordException providerReport = null;
            IEventRecordException traceReport = null;

            var provider = new Provider(ProviderId);
            provider.OnEventRef += (in EventRecordRef record) => throw thrown;
            provider.OnUnhandledException += e =>
            {
                order += "p";
                providerReport = e;
            };

            using (var trace = new UserTrace())
            {
                trace.StopOnHandlerException = false;
                trace.DefaultUnhandledException = e =>
                {
                    order += "t";
                    traceReport = e;
                };
                trace.Enable(provider);

                using (EventSchema.Use(Declaration()))
                using (SynthRecord record = BuildRecord())
                using (var proxy = new Proxy(trace))
                {
                    var error = Assert.Throws<InvalidOperationException>(() => proxy.PushEvent(record));
                    Assert.Same(thrown, error);
                }

                Assert.Equal("pt", order);
                Assert.Same(thrown, providerReport.Exception);
                Assert.Same(thrown, traceReport.Exception);
                Assert.False(providerReport.Stopping);
                Assert.False(traceReport.Stopping);
                Assert.Equal(1UL, trace.UnhandledExceptions);
            }
        }

        [Fact]
        public void ProviderReportingExceptionDoesNotHideTraceReport()
        {
            var reportingFailure = new ApplicationException("reporting failed");
            IEventRecordException traceReport = null;
            try
            {
                TraceContext.LastReportingException = null;

                var provider = new Provider(ProviderId);
                provider.OnEventRef += (in EventRecordRef record) => throw new InvalidOperationException("handler failed");
                provider.OnUnhandledException += e => throw reportingFailure;

                using (var trace = new UserTrace())
                {
                    trace.StopOnHandlerException = false;
                    trace.DefaultUnhandledException = e => traceReport = e;
                    trace.Enable(provider);

                    using (EventSchema.Use(Declaration()))
                    using (SynthRecord record = BuildRecord())
                    using (var proxy = new Proxy(trace))
                    {
                        Assert.Throws<InvalidOperationException>(() => proxy.PushEvent(record));
                    }

                    Assert.NotNull(traceReport);
                    Assert.Same(reportingFailure, TraceContext.LastReportingException);
                }
            }
            finally
            {
                TraceContext.LastReportingException = null;
            }
        }

        [Fact]
        public void KernelProviderRoutesByHeaderProviderId()
        {
            int providerHits = 0;
            int defaults = 0;

            var provider = new KernelProvider(flags: 0, ProviderId);
            provider.OnEventRef += (in EventRecordRef record) => providerHits++;

            using (var trace = new KernelTrace())
            {
                trace.DefaultEventRef = (in EventRecordRef record) => defaults++;
                trace.Enable(provider);

                using (EventSchema.Use(Declaration()))
                using (SynthRecord record = BuildRecord())
                using (var proxy = new Proxy(trace))
                {
                    proxy.PushEvent(record);
                }

                Assert.Equal(1, providerHits);
                Assert.Equal(0, defaults);
            }
        }

        [Fact]
        public void TraceRegistryGrowsAndRejectsOutOfRangeLookups()
        {
            var contexts = new TraceContext[9];
            var indexes = new int[contexts.Length];
            int registered = 0;

            try
            {
                for (int i = 0; i < contexts.Length; i++)
                {
                    contexts[i] = new TraceContext();
                    indexes[i] = TraceRegistry.Register(contexts[i]);
                    registered = i + 1;
                    Assert.Same(contexts[i], TraceRegistry.Get(indexes[i]));
                }

                Assert.Null(TraceRegistry.Get(-1));
                Assert.Null(TraceRegistry.Get(int.MaxValue));
            }
            finally
            {
                for (int i = 0; i < registered; i++)
                {
                    TraceRegistry.Unregister(indexes[i], contexts[i]);
                }

                for (int i = 0; i < contexts.Length; i++)
                {
                    contexts[i]?.Dispose();
                }
            }
        }

        private static SynthRecord BuildRecordWithoutDeclaredSchema()
        {
            IDisposable scope = EventSchema.Use(Declaration());
            try
            {
                return BuildRecord();
            }
            finally
            {
                scope.Dispose();
            }
        }

        private static SynthRecord BuildRecord()
        {
            using (var builder = new RecordBuilder(ProviderId, id: 21, version: 0))
            {
                builder.AddValue("Value", 42u);
                return builder.Pack();
            }
        }

        private static EventSchema Declaration()
        {
            return EventSchema
                .Create("Krabs-Managed-Trace-Context", ProviderId, id: 21, version: 0)
                .Named("Routed")
                .UInt32("Value");
        }
    }
}
