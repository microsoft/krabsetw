using System;
using System.Threading;
using Xunit;

namespace Microsoft.O365.Security.ETW.Tests
{
    /// <summary>
    /// Covers the counters <see cref="UserTrace.QueryStats"/> reports.
    /// </summary>
    /// <remarks>
    /// krabs increments its single counter in krabs::trace::on_event, before forwarding to any
    /// provider (trace.hpp:447), and derives eventsTotal as that count plus the events ETW
    /// reports lost (trace.hpp:61). So EventsHandled is every event the consumer saw, not the
    /// subset some provider claimed. A real session always receives at least one event no
    /// provider claims -- the EventTrace header ETW emits when processing starts -- which is
    /// what separates the two readings.
    /// </remarks>
    [Collection("etw")]
    public class TraceStatsTests
    {
        [Fact]
        public void EventsHandledCountsEveryEventNotJustTheOnesAProviderClaimed()
        {
            var provider = new Provider(TestTraceLoggingSource.ProviderGuid) { Any = 0 };
            int matched = 0;

            using (var seen = new ManualResetEventSlim(false))
            {
                var filter = new EventFilter(Filter.EventNameIs("Interesting") && EtwHarness.ThisProcess);
                filter.OnEventRef += (in EventRecordRef record) =>
                {
                    Interlocked.Increment(ref matched);
                    seen.Set();
                };
                provider.AddFilter(filter);

                using (var trace = new UserTrace("Krabs-Managed-Tests-" + Guid.NewGuid().ToString("N")))
                {
                    trace.Enable(provider);
                    trace.Open();

                    var processing = new Thread(trace.Start) { IsBackground = true };
                    processing.Start();

                    TraceStats stats;
                    int claimed;

                    try
                    {
                        var deadline = DateTime.UtcNow + EtwHarness.Timeout;

                        while (DateTime.UtcNow < deadline && !seen.IsSet)
                        {
                            TestTraceLoggingSource.Log.Interesting("a", 1);
                            seen.Wait(TimeSpan.FromMilliseconds(250));
                        }

                        Assert.True(seen.IsSet, "The provider never delivered an event.");

                        // Emission has stopped; let the session drain so the claimed count
                        // settles. Read it *before* the stats, so it can only understate what
                        // the stats already counted.
                        Thread.Sleep(TimeSpan.FromMilliseconds(500));
                        claimed = Volatile.Read(ref matched);

                        stats = trace.QueryStats();
                    }
                    finally
                    {
                        trace.Stop();
                        processing.Join(EtwHarness.Timeout);
                    }

                    Assert.True(claimed > 0, "No event was routed to the provider.");

                    // The unclaimed EventTrace header makes this strict. Counting only routed
                    // events would make it an equality.
                    Assert.True(
                        stats.EventsHandled > (ulong)claimed,
                        "EventsHandled (" + stats.EventsHandled + ") should exceed the " +
                        claimed + " events a provider claimed, because it counts every event.");

                    Assert.Equal(stats.EventsHandled + stats.EventsLost, stats.EventsTotal);
                }
            }
        }
    }
}
