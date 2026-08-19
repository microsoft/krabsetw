using System;
using System.Threading;
using Microsoft.O365.Security.ETW.Testing;
using Xunit;

namespace Microsoft.O365.Security.ETW.Tests
{
    /// <summary>
    /// Covers the counters <see cref="UserTrace.QueryStats"/> reports.
    /// </summary>
    /// <remarks>
    /// krabs increments a single counter in krabs::trace::on_event, before forwarding to any
    /// provider (trace.hpp:447), and derives eventsTotal as that count plus the events ETW
    /// reports lost (trace.hpp:61). So EventsHandled is every event the consumer saw, not the
    /// subset some provider claimed.
    /// <para>
    /// Every event is either routed to a provider or handed to the default handler, so
    /// EventsHandled must equal the sum of the two. Counting only routed events -- which is
    /// what the port did before -- breaks that identity as soon as the session receives an
    /// event no enabled provider owns, such as the EventTrace header ETW emits when
    /// processing starts. Whether such an event lands inside the test's window is not
    /// guaranteed, so the identity is asserted rather than a strict inequality.
    /// </para>
    /// </remarks>
    [Collection("etw")]
    public class TraceStatsTests
    {
        [Fact]
        public void EventsHandledCountsRoutedAndUnroutedEventsAlike()
        {
            var provider = new Provider(TestTraceLoggingSource.ProviderGuid) { Any = 0 };
            int routed = 0;
            int unrouted = 0;

            using (var seen = new ManualResetEventSlim(false))
            {
                // Provider level, so this sees every event carrying the provider's GUID, not
                // just the ones a filter would accept. A filter's hit count is not the same
                // thing as the routed count and cannot be substituted here.
                provider.OnEventRef += (in EventRecordRef record) =>
                {
                    Interlocked.Increment(ref routed);
                    seen.Set();
                };

                using (var trace = new UserTrace("Krabs-Managed-Tests-" + Guid.NewGuid().ToString("N")))
                {
                    trace.DefaultEventRef = (in EventRecordRef record) =>
                    {
                        Interlocked.Increment(ref unrouted);
                    };

                    trace.Enable(provider);
                    trace.Open();

                    var processing = new Thread(trace.Start) { IsBackground = true };
                    processing.Start();

                    TraceStats stats;
                    int matched;
                    int missed;

                    try
                    {
                        var deadline = DateTime.UtcNow + EtwHarness.Timeout;

                        while (DateTime.UtcNow < deadline && !seen.IsSet)
                        {
                            TestTraceLoggingSource.Log.Interesting("a", 1);
                            seen.Wait(TimeSpan.FromMilliseconds(250), TestContext.Current.CancellationToken);
                        }

                        Assert.True(seen.IsSet, "The provider never delivered an event.");

                        // Emission has stopped; let the session drain so both counts settle,
                        // then read them before the stats so they cannot overstate what the
                        // stats already counted.
                        Thread.Sleep(TimeSpan.FromMilliseconds(500));
                        matched = Volatile.Read(ref routed);
                        missed = Volatile.Read(ref unrouted);

                        stats = trace.QueryStats();
                    }
                    finally
                    {
                        trace.Stop();
                        processing.Join(EtwHarness.Timeout);
                    }

                    Assert.True(matched > 0, "No event was routed to the provider.");

                    // Counting only routed events drops the unrouted ones from EventsHandled
                    // and breaks this.
                    Assert.Equal((ulong)(matched + missed), stats.EventsHandled);

                    // EventsTotal folds in the events ETW reports lost, as krabs does.
                    Assert.Equal(stats.EventsHandled + stats.EventsLost, stats.EventsTotal);
                }
            }
        }

        /// <summary>
        /// The deterministic form of the above. A live session only receives an unclaimed
        /// event if ETW happens to inject one inside the test's window, so the rule is pinned
        /// here instead, by pushing an event for a provider GUID nothing is enabled for.
        /// </summary>
        [Fact]
        public void EventsHandledCountsEventsNoProviderClaimed()
        {
            var provider = new Provider(EnabledId);
            int routed = 0;

            provider.OnEventRef += (in EventRecordRef record) => routed++;

            using (EventSchema.Use(Declaration(EnabledId), Declaration(UnclaimedId)))
            {
                var trace = new UserTrace();
                var proxy = new Proxy(trace);

                trace.Enable(provider);

                Push(proxy, EnabledId);
                Push(proxy, EnabledId);

                // No provider is enabled for this GUID, so nothing routes it.
                Push(proxy, UnclaimedId);

                Assert.Equal(2, routed);

                // Counting only routed events would report 2.
                Assert.Equal(3UL, trace.EventsHandledCount);
            }
        }

        private static readonly Guid EnabledId =
            Guid.Parse("8c1f4a62-9d73-4e58-b0a1-5e2c7f38d940");

        private static readonly Guid UnclaimedId =
            Guid.Parse("d4b90e17-3a55-4c26-9f8b-61ad02e7c583");

        private static void Push(Proxy proxy, Guid providerId)
        {
            using (var builder = new RecordBuilder(providerId, id: 1, version: 0))
            {
                builder.AddValue("ProcessId", 4321u);

                using (SynthRecord record = builder.Pack())
                {
                    proxy.PushEvent(record);
                }
            }
        }

        private static EventSchema Declaration(Guid providerId)
        {
            return EventSchema
                .Create("Krabs-Managed-Stats-Test", providerId, id: 1, version: 0)
                .Named("StatsEvent")
                .UInt32("ProcessId");
        }
    }
}
