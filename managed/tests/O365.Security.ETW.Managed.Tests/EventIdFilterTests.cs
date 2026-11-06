using System;
using System.Collections.Generic;
using Microsoft.O365.Security.ETW.Testing;
using Xunit;

namespace Microsoft.O365.Security.ETW.Tests
{
    /// <summary>
    /// The managed counterpart of the event id tests in tests\krabstests\test_filter.cpp.
    /// </summary>
    /// <remarks>
    /// The event ids handed to <see cref="EventFilter"/> are also pushed into ETW as an
    /// EVENT_FILTER_TYPE_EVENT_ID descriptor, but that push-down is an optimisation rather
    /// than a guarantee: ETW does not apply it to MOF or WPP events, it is dropped when the
    /// id count exceeds MAX_EVENT_FILTER_EVENT_ID_COUNT, and the ids of every filter on a
    /// provider are unioned before being pushed. Each filter therefore re-tests its own ids,
    /// and that user-mode re-test is what these cover.
    ///
    /// Events are driven through Testing.Proxy against a declared schema rather than emitted
    /// from a live EventSource. Both of EventFilter's event surfaces are gated on a resolvable
    /// schema, matching CallbackBridge::EventNotification in the C++/CLI wrapper, and a
    /// manifest-based EventSource publishes its manifest in-band where TDH cannot reach it.
    /// A declared schema keeps these tests about filtering rather than about decodability.
    /// </remarks>
    public class EventIdFilterTests
    {
        private static readonly Guid ProviderId =
            Guid.Parse("3f5c9a7e-2d18-4b6f-8e0a-c41d7b93f206");

        [Fact]
        public void ForwardsEventsWithAMatchingId()
        {
            Assert.True(Run(new EventFilter(1), 1) > 0);
        }

        [Fact]
        public void DoesNotForwardEventsWithADifferentId()
        {
            Assert.Equal(0, Run(new EventFilter(2), 1));
        }

        [Fact]
        public void ForwardsEventsMatchingAnyIdInTheList()
        {
            Assert.True(Run(new EventFilter(new List<ushort> { 2, 1 }), 1) > 0);
        }

        [Fact]
        public void StillAppliesThePredicate()
        {
            Assert.Equal(0, Run(new EventFilter(1, Filter.NoEvent()), 1));
        }

        /// <summary>
        /// Two filters on one provider union their ids into a single ETW descriptor, so each
        /// filter is offered the other's events and has to reject them itself.
        /// </summary>
        [Fact]
        public void FiltersSharingAProviderDoNotSeeEachOthersEvents()
        {
            int ones = 0;
            int twos = 0;

            var first = new EventFilter(1);
            first.OnEventRef += (in EventRecordRef record) =>
            {
                Assert.Equal(1, record.Id);
                ones++;
            };

            var second = new EventFilter(2);
            second.OnEventRef += (in EventRecordRef record) =>
            {
                Assert.Equal(2, record.Id);
                twos++;
            };

            var provider = new Provider(ProviderId);
            provider.AddFilter(first);
            provider.AddFilter(second);

            using (EventSchema.Use(Declaration(1), Declaration(2)))
            {
                var trace = new UserTrace();
                var proxy = new Proxy(trace);
                trace.Enable(provider);

                PushEvent(proxy, 1);
                PushEvent(proxy, 2);
            }

            Assert.Equal(1, ones);
            Assert.Equal(1, twos);
        }

        private static int Run(EventFilter filter, ushort emittedId)
        {
            int hits = 0;

            filter.OnEventRef += (in EventRecordRef record) => hits++;

            var provider = new Provider(ProviderId);
            provider.AddFilter(filter);

            using (EventSchema.Use(Declaration(emittedId)))
            {
                var trace = new UserTrace();
                var proxy = new Proxy(trace);
                trace.Enable(provider);

                PushEvent(proxy, emittedId);
            }

            return hits;
        }

        private static void PushEvent(Proxy proxy, ushort id)
        {
            using (var builder = new RecordBuilder(ProviderId, id, version: 0))
            {
                builder.AddValue("ProcessId", 4321u);

                using (SynthRecord record = builder.Pack())
                {
                    proxy.PushEvent(record);
                }
            }
        }

        private static EventSchema Declaration(ushort id)
        {
            return EventSchema
                .Create("Krabs-Managed-Filter-Test", ProviderId, id, version: 0)
                .Named("Event" + id)
                .UInt32("ProcessId");
        }
    }
}
