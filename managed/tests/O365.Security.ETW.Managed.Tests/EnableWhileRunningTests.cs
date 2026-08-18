using System;
using System.Threading;
using Xunit;

namespace Microsoft.O365.Security.ETW.Tests
{
    /// <summary>
    /// Covers enabling a provider on a trace that is already processing events.
    /// </summary>
    /// <remarks>
    /// This is the one thing a trace does from two threads at once: the caller replaces the
    /// provider set while the processing thread is reading it. krabs has no equivalent -- it
    /// has no public enable-while-running -- so nothing in the parity suite covers it.
    /// </remarks>
    [Collection("etw")]
    public class EnableWhileRunningTests
    {
        [Fact]
        public void AProviderEnabledOnARunningTraceReceivesEvents()
        {
            var first = new Provider(TestTraceLoggingSource.ProviderGuid) { Any = 0 };
            var second = new Provider(TestArraySource.ProviderGuid) { Any = 0 };

            using (var firstSeen = new ManualResetEventSlim(false))
            using (var secondSeen = new ManualResetEventSlim(false))
            {
                var firstFilter = new EventFilter(Filter.EventNameIs("Interesting") && EtwHarness.ThisProcess);
                firstFilter.OnEventRef += (in EventRecordRef record) => firstSeen.Set();
                first.AddFilter(firstFilter);

                var secondFilter = new EventFilter(Filter.EventNameIs("Sized") && EtwHarness.ThisProcess);
                secondFilter.OnEventRef += (in EventRecordRef record) => secondSeen.Set();
                second.AddFilter(secondFilter);

                using (var trace = new UserTrace("Krabs-Managed-Tests-" + Guid.NewGuid().ToString("N")))
                {
                    trace.Enable(first);
                    trace.Open();

                    var processing = new Thread(trace.Start) { IsBackground = true };
                    processing.Start();

                    try
                    {
                        Assert.True(
                            EmitUntil(firstSeen, () => TestTraceLoggingSource.Log.Interesting("a", 1)),
                            "The provider enabled before Start never delivered an event.");

                        // The processing thread is inside ProcessTrace and reading the
                        // provider set as this replaces it.
                        trace.Enable(second);

                        Assert.True(
                            EmitUntil(secondSeen, () => TestArraySource.Log.Sized(new[] { 1 }, 2)),
                            "The provider enabled while the trace was running never delivered an event.");

                        // The first provider has to survive the republish.
                        firstSeen.Reset();

                        Assert.True(
                            EmitUntil(firstSeen, () => TestTraceLoggingSource.Log.Interesting("b", 2)),
                            "The provider enabled before Start stopped delivering after a second was added.");
                    }
                    finally
                    {
                        trace.Stop();
                        processing.Join(EtwHarness.Timeout);
                    }
                }
            }
        }

        private static bool EmitUntil(ManualResetEventSlim signal, Action emit)
        {
            DateTime deadline = DateTime.UtcNow + EtwHarness.Timeout;

            while (DateTime.UtcNow < deadline && !signal.IsSet)
            {
                emit();
                signal.Wait(TimeSpan.FromMilliseconds(250));
            }

            return signal.IsSet;
        }
    }
}
