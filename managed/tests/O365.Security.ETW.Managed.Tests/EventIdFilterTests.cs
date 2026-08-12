using System;
using System.Collections.Generic;
using System.Threading;
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
    /// provider are unioned before being pushed. Each filter therefore re-tests its own ids.
    /// </remarks>
    [Collection("etw")]
    public class EventIdFilterTests
    {
        [Fact]
        public void ForwardsEventsWithAMatchingId()
        {
            Assert.True(Run(new EventFilter(1, EtwHarness.ThisProcess), () => TestEventSource.Log.Interesting("a", 1), EtwHarness.Timeout) > 0);
        }

        [Fact]
        public void DoesNotForwardEventsWithADifferentId()
        {
            Assert.Equal(0, Run(new EventFilter(2, EtwHarness.ThisProcess), () => TestEventSource.Log.Interesting("a", 1), EtwHarness.NegativeTimeout));
        }

        [Fact]
        public void ForwardsEventsMatchingAnyIdInTheList()
        {
            Assert.True(Run(new EventFilter(new List<ushort> { 2, 1 }, EtwHarness.ThisProcess), () => TestEventSource.Log.Interesting("a", 1), EtwHarness.Timeout) > 0);
        }

        [Fact]
        public void StillAppliesThePredicate()
        {
            Assert.Equal(0, Run(new EventFilter(1, Filter.NoEvent() && EtwHarness.ThisProcess), () => TestEventSource.Log.Interesting("a", 1), EtwHarness.NegativeTimeout));
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
            var signal = new ManualResetEventSlim();

            var first = new EventFilter(1, EtwHarness.ThisProcess);
            first.OnEventRef += (in EventRecordRef record) =>
            {
                Assert.Equal(1, record.Id);
                Interlocked.Increment(ref ones);
            };

            var second = new EventFilter(2, EtwHarness.ThisProcess);
            second.OnEventRef += (in EventRecordRef record) =>
            {
                Assert.Equal(2, record.Id);
                if (Interlocked.Increment(ref twos) > 0)
                {
                    signal.Set();
                }
            };

            var provider = new Provider(TestEventSource.ProviderGuid) { Any = 0 };
            provider.AddFilter(first);
            provider.AddFilter(second);

            EtwHarness.Run(provider, signal, () =>
            {
                TestEventSource.Log.Interesting("a", 1);
                TestEventSource.Log.Boring(7);
            });

            Assert.True(ones > 0, "The event id 1 filter never fired.");
            Assert.True(twos > 0, "The event id 2 filter never fired.");
        }

        private static int Run(EventFilter filter, Action emit, TimeSpan timeout)
        {
            int hits = 0;
            var signal = new ManualResetEventSlim();

            filter.OnEventRef += (in EventRecordRef record) =>
            {
                Interlocked.Increment(ref hits);
                signal.Set();
            };

            var provider = new Provider(TestEventSource.ProviderGuid) { Any = 0 };
            provider.AddFilter(filter);

            // A non-matching filter never signals, so this deliberately runs to the
            // supplied deadline.
            EtwHarness.Run(provider, signal, emit, timeout);

            return hits;
        }
    }
}
