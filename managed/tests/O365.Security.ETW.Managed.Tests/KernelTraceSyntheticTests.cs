using System;
using System.Collections.Generic;
using Microsoft.O365.Security.ETW.Testing;
using Xunit;

namespace Microsoft.O365.Security.ETW.Tests
{
    /// <summary>
    /// Drives <see cref="KernelTrace"/> through the synthetic testing proxy, proving kernel
    /// traces publish providers and use the same handler-failure surfaces as live callbacks.
    /// </summary>
    public class KernelTraceSyntheticTests
    {
        private static readonly Guid FirstProviderId = Guid.Parse("1d594bf3-1020-41e1-96ff-d3d029d0039b");
        private static readonly Guid SecondProviderId = Guid.Parse("81e38d9b-8f97-4c1f-a865-7341e57a3d0a");

        [Fact]
        public void ConstructorAndCallbackPropertiesRoundTrip()
        {
            var name = "Krabs-Managed-Kernel-Synthetic-" + Guid.NewGuid().ToString("N");
            using (var trace = new KernelTrace(name))
            {
                IEventRecordDelegate defaultEvent = _ => { };
                IEventRecordDelegate obsoleteDefaultEvent = _ => { };
                IEventRecordMetadataDelegate defaultMetadata = _ => { };
                EventRecordDelegate defaultEventRef = (in EventRecordRef record) => { };
                EventRecordErrorDelegate defaultError = _ => { };
                EventRecordExceptionDelegate unhandled = _ => { };

                trace.DefaultEvent = defaultEvent;
                trace.DefaultMetadata = defaultMetadata;
                trace.DefaultEventRef = defaultEventRef;
                trace.DefaultError = defaultError;
                trace.DefaultUnhandledException = unhandled;
                trace.StopOnHandlerException = false;
#pragma warning disable CS0618
                trace.SetDefaultEventCallback(obsoleteDefaultEvent);
#pragma warning restore CS0618

                Assert.Equal(name, trace.Name);
                Assert.Equal(0ul, trace.BuffersProcessed);
                Assert.Equal(0ul, trace.UnhandledExceptions);
                Assert.Same(obsoleteDefaultEvent, trace.DefaultEvent);
                Assert.Same(defaultMetadata, trace.DefaultMetadata);
                Assert.Same(defaultEventRef, trace.DefaultEventRef);
                Assert.Same(defaultError, trace.DefaultError);
                Assert.Same(unhandled, trace.DefaultUnhandledException);
                Assert.False(trace.StopOnHandlerException);
            }
        }

        [Fact]
        public void NullArgumentsAreRejectedBeforeAnyNativeSessionIsOpened()
        {
            using (var trace = new KernelTrace())
            {
                Assert.Throws<ArgumentNullException>(() => new KernelTrace(null));
                Assert.Throws<ArgumentNullException>(() => trace.Enable(null));
                Assert.Throws<ArgumentNullException>(() => trace.SetTraceProperties(null));
            }
        }

        [Fact]
        public void ProvidersEnabledAfterSyntheticDispatchArePublishedOnNextPush()
        {
            int first = 0;
            int second = 0;
            var firstProvider = new KernelProvider(0x1u, FirstProviderId);
            var secondProvider = new KernelProvider(0x2u, SecondProviderId);
            firstProvider.OnEventRef += (in EventRecordRef record) => first++;
            secondProvider.OnEventRef += (in EventRecordRef record) => second++;

            using (EventSchema.Use(Declaration(FirstProviderId), Declaration(SecondProviderId)))
            using (var trace = new KernelTrace())
            {
                using var proxy = new Proxy(trace);
                trace.Enable(firstProvider);
                Push(proxy, FirstProviderId);

                trace.Enable(secondProvider);
                Push(proxy, SecondProviderId);
            }

            Assert.Equal(1, first);
            Assert.Equal(1, second);
        }

        [Fact]
        public void HandlerExceptionIsReportedAndStopsFurtherSyntheticDispatchByDefault()
        {
            int delivered = 0;
            var providerReports = new List<IEventRecordException>();
            var traceReports = new List<IEventRecordException>();
            var provider = new KernelProvider(0x4u, FirstProviderId);
            provider.OnEventRef += (in EventRecordRef record) =>
            {
                delivered++;
                throw new InvalidOperationException("kernel handler failed");
            };
            provider.OnUnhandledException += e => providerReports.Add(e);

            using (EventSchema.Use(Declaration(FirstProviderId)))
            using (var trace = new KernelTrace())
            {
                trace.DefaultUnhandledException = e => traceReports.Add(e);
                using var proxy = new Proxy(trace);
                trace.Enable(provider);

                PushAndSwallow(proxy, FirstProviderId);
                PushAndSwallow(proxy, FirstProviderId);

                Assert.Equal(1ul, trace.UnhandledExceptions);
            }

            Assert.Equal(1, delivered);
            Assert.Single(providerReports);
            Assert.Single(traceReports);
            Assert.Same(providerReports[0].Exception, traceReports[0].Exception);
            Assert.True(traceReports[0].Stopping);
        }

        private static void Push(Proxy proxy, Guid providerId)
        {
            using (var builder = new RecordBuilder(providerId, id: 11, version: 0))
            {
                builder.AddValue("ProcessId", 4321u);

                using (SynthRecord record = builder.Pack())
                {
                    proxy.PushEvent(record);
                }
            }
        }

        private static void PushAndSwallow(Proxy proxy, Guid providerId)
        {
            try
            {
                Push(proxy, providerId);
            }
            catch (InvalidOperationException)
            {
            }
        }

        private static EventSchema Declaration(Guid providerId)
        {
            return EventSchema
                .Create("Contoso-Kernel-Trace", providerId, id: 11, version: 0)
                .Named("KernelTraceEvent")
                .UInt32("ProcessId");
        }
    }

    [Collection("etw")]
    public class KernelTraceEtwTests
    {
        [Fact]
        public void QueryStatsOnAnUnopenedTraceReportsTheControlTraceFailure()
        {
            using (var trace = new KernelTrace("Krabs-Managed-Missing-" + Guid.NewGuid().ToString("N")))
            {
                TraceException ex = Assert.Throws<TraceException>(() => trace.QueryStats());

                Assert.NotEqual(0, ex.Status);
            }
        }
    }
}
