using System;
using System.Collections.Generic;
using Microsoft.O365.Security.ETW.Testing;
using Xunit;

namespace Microsoft.O365.Security.ETW.Tests
{
    /// <summary>
    /// Covers kernel-provider dispatch routing: metadata always sees a claimed record,
    /// event handlers and filters require a resolved schema, and decode failures are
    /// reported once at the provider boundary.
    /// </summary>
    public class KernelDispatchTests
    {
        private static readonly Guid ProviderId = Guid.Parse("7bf1cf62-1d4d-42a2-9718-0c43af0e3af4");
        private static readonly Guid OtherProviderId = Guid.Parse("57876aaf-9178-4499-b28c-488290800cc9");

        [Fact]
        public void EventHandlersRunBeforeFiltersWhenSchemaResolves()
        {
            var calls = new List<string>();
            var provider = new KernelProvider(0x1u, ProviderId);
            var filter = new EventFilter(7);
            provider.OnMetadata += _ => calls.Add("metadata");
            provider.OnEventRef += (in EventRecordRef record) => calls.Add("event-ref:" + record.Id);
            provider.OnEvent += record => calls.Add("event:" + record.Id);
            filter.OnEventRef += (in EventRecordRef record) => calls.Add("filter-ref:" + record.Id);
            filter.OnEvent += record => calls.Add("filter:" + record.Id);
            provider.AddFilter(filter);

            using (EventSchema.Use(Declaration()))
            using (var trace = new KernelTrace())
            {
                using var proxy = new Proxy(trace);
                trace.Enable(provider);
                Push(proxy, ProviderId, 7);
            }

            Assert.Equal(
                new[] { "metadata", "event-ref:7", "event:7", "filter-ref:7", "filter:7" },
                calls);
        }

        [Fact]
        public void MetadataRunsWithoutHandlersOrSchema()
        {
            int metadata = 0;
            var provider = new KernelProvider(0x2u, ProviderId);
            provider.OnMetadata += record =>
            {
                metadata++;
                Assert.Equal(ProviderId, record.ProviderId);
            };

            using (var trace = new KernelTrace())
            {
                using var proxy = new Proxy(trace);
                trace.Enable(provider);
                PushAfterSchemaDisposed(proxy, ProviderId, 7);
            }

            Assert.Equal(1, metadata);
        }

        [Fact]
        public void SchemaFailureRaisesProviderErrorAndSkipsEventsAndFilters()
        {
            int events = 0;
            int filters = 0;
            IEventRecordError error = null;
            var provider = new KernelProvider(0x4u, ProviderId);
            var filter = new EventFilter(7);
            provider.OnEventRef += (in EventRecordRef record) => events++;
            provider.OnEvent += _ => events++;
            provider.OnError += e => error = e;
            filter.OnEventRef += (in EventRecordRef record) => filters++;
            provider.AddFilter(filter);

            using (var trace = new KernelTrace())
            {
                using var proxy = new Proxy(trace);
                trace.Enable(provider);
                PushAfterSchemaDisposed(proxy, ProviderId, 7);
            }

            Assert.NotNull(error);
            Assert.Contains(ProviderId.ToString(), error.Message, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("7", error.Message, StringComparison.Ordinal);
            Assert.Equal(0, events);
            Assert.Equal(0, filters);
        }

        [Fact]
        public void UnclaimedKernelEventReachesDefaultHandlerAndIsCounted()
        {
            int defaults = 0;
            int providerHits = 0;
            var provider = new KernelProvider(0x8u, ProviderId);
            provider.OnEventRef += (in EventRecordRef record) => providerHits++;

            using (EventSchema.Use(Declaration()))
            using (var trace = new KernelTrace())
            {
                trace.DefaultEventRef = (in EventRecordRef record) => defaults++;
                using var proxy = new Proxy(trace);
                trace.Enable(provider);

                Push(proxy, ProviderId, 7);
                using (EventSchema.Use(EventSchema
                    .Create("Contoso-Unclaimed-Kernel-Dispatch", OtherProviderId, id: 7, version: 0)
                    .Named("UnclaimedKernelDispatchEvent")
                    .UInt32("ProcessId")))
                {
                    Push(proxy, OtherProviderId, 7);
                }

                Assert.Equal(1, providerHits);
                Assert.Equal(1, defaults);
            }
        }

        [Fact]
        public void AddFilterRejectsNull()
        {
            var provider = new KernelProvider(0x10u, ProviderId);

            Assert.Throws<ArgumentNullException>(() => provider.AddFilter(null));
        }

        private static void PushAfterSchemaDisposed(Proxy proxy, Guid providerId, ushort id)
        {
            SynthRecord record;
            using (EventSchema.Use(Declaration()))
            using (var builder = new RecordBuilder(providerId, id, version: 0))
            {
                builder.AddValue("ProcessId", 4321u);
                record = builder.Pack();
            }

            using (record)
            {
                proxy.PushEvent(record);
            }
        }

        private static void Push(Proxy proxy, Guid providerId, ushort id)
        {
            using (var builder = new RecordBuilder(providerId, id, version: 0))
            {
                builder.AddValue("ProcessId", 4321u);

                using (SynthRecord record = builder.Pack())
                {
                    proxy.PushEvent(record);
                }
            }
        }

        private static EventSchema Declaration()
        {
            return EventSchema
                .Create("Contoso-Kernel-Dispatch", ProviderId, id: 7, version: 0)
                .Named("KernelDispatchEvent")
                .UInt32("ProcessId");
        }
    }
}

