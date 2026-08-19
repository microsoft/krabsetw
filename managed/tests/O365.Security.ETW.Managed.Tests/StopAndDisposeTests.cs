using System;
using System.Diagnostics;
using System.Threading;
using Xunit;

namespace Microsoft.O365.Security.ETW.Tests
{
    /// <summary>
    /// Covers the split between signalling a trace to stop and releasing what its callback
    /// reaches.
    /// </summary>
    /// <remarks>
    /// <see cref="UserTrace.Stop"/> only signals, as krabs' does; the registration and the
    /// logger name are released by <see cref="UserTrace.Dispose"/>. Keeping them allocated
    /// past Stop is what makes it safe for Stop not to wait: ProcessTrace goes on draining
    /// buffered events for a while afterwards, and everything it reaches through is still
    /// there. A caller that needs handlers to have quiesced waits for Start to return.
    /// </remarks>
    [Collection("etw")]
    public class StopAndDisposeTests
    {
        /// <summary>
        /// Stop used to wait for ProcessTrace to return while holding the lock that Enable
        /// needs, so a handler calling back into its own trace deadlocked both until the wait
        /// expired. Stop signals and returns, so there is nothing to deadlock against.
        /// </summary>
        [Fact]
        public void StopDoesNotWaitForAHandlerThatIsCallingBackIntoTheTrace()
        {
            var provider = new Provider(TestTraceLoggingSource.ProviderGuid) { Any = 0 };
            var second = new Provider(TestArraySource.ProviderGuid) { Any = 0 };

            using (var inHandler = new ManualResetEventSlim(false))
            using (var releaseHandler = new ManualResetEventSlim(false))
            using (var trace = new UserTrace("Krabs-StopDispose-" + Guid.NewGuid().ToString("N")))
            {
                var filter = new EventFilter(Filter.EventNameIs("Interesting") && EtwHarness.ThisProcess);

                filter.OnEvent += record =>
                {
                    inHandler.Set();

                    // Blocks until the test releases it, then calls back into the trace.
                    // Enable takes the same lock Stop does.
                    releaseHandler.Wait(TimeSpan.FromSeconds(30));

                    try
                    {
                        trace.Enable(second);
                    }
                    catch (TraceException)
                    {
                        // Enabling on a session that has since been stopped is allowed to
                        // fail; the point of the test is that neither call hangs.
                    }
                };

                provider.AddFilter(filter);
                trace.Enable(provider);
                trace.Open();

                var processing = new Thread(trace.Start) { IsBackground = true };
                processing.Start();

                var emitting = new Thread(() =>
                {
                    while (!inHandler.IsSet)
                    {
                        TestTraceLoggingSource.Log.Interesting("a", 1);
                        Thread.Sleep(50);
                    }
                })
                { IsBackground = true };
                emitting.Start();

                Assert.True(inHandler.Wait(TimeSpan.FromSeconds(30), TestContext.Current.CancellationToken), "The handler never ran.");

                var elapsed = Stopwatch.StartNew();
                trace.Stop();
                elapsed.Stop();

                releaseHandler.Set();

                Assert.True(
                    elapsed.Elapsed < TimeSpan.FromSeconds(2),
                    "Stop blocked for " + elapsed.Elapsed.TotalSeconds.ToString("F1") +
                    "s. It is meant to signal and return, not wait for handlers.");

                emitting.Join(TimeSpan.FromSeconds(10));
                processing.Join(TimeSpan.FromSeconds(30));
            }
        }

        /// <summary>
        /// A second Start while the first is inside ProcessTrace would share the one thread
        /// slot and the one drain event, so the first call's exit would tell Dispose the
        /// trace had quiesced while the second was still consuming -- and Dispose would then
        /// free the schema blobs and logger name that ETW still reaches through.
        /// </summary>
        [Fact]
        public void ASecondStartIsRejectedWhileTheFirstIsProcessing()
        {
            var provider = new Provider(TestTraceLoggingSource.ProviderGuid) { Any = 0 };

            using (var processing = new ManualResetEventSlim(false))
            using (var trace = new UserTrace("Krabs-DoubleStart-" + Guid.NewGuid().ToString("N")))
            {
                var filter = new EventFilter(EtwHarness.ThisProcess);
                filter.OnEvent += record => processing.Set();

                provider.AddFilter(filter);
                trace.Enable(provider);
                trace.Open();

                var first = new Thread(trace.Start) { IsBackground = true };
                first.Start();

                var emitting = new Thread(() =>
                {
                    while (!processing.IsSet)
                    {
                        TestTraceLoggingSource.Log.Interesting("a", 1);
                        Thread.Sleep(50);
                    }
                })
                { IsBackground = true };
                emitting.Start();

                try
                {
                    // Waiting for a delivered event is what makes this deterministic: it
                    // proves the first Start is inside ProcessTrace, so the second one is
                    // racing a live processor rather than an unstarted trace.
                    Assert.True(
                        processing.Wait(TimeSpan.FromSeconds(30), TestContext.Current.CancellationToken),
                        "The trace never began processing.");

                    Assert.Throws<InvalidOperationException>(() => trace.Start());
                }
                finally
                {
                    trace.Stop();
                    emitting.Join(TimeSpan.FromSeconds(10));
                    first.Join(TimeSpan.FromSeconds(30));
                }
            }
        }

        /// <summary>
        /// Deferring the release to Dispose must not turn every Open/Stop cycle into a leaked
        /// registration, which is what would happen if Open registered unconditionally.
        /// </summary>
        [Fact]
        public void OpenAndStopCyclesDoNotAccumulateRegistrations()
        {
            int before = TraceRegistry.InUse;

            using (var trace = new UserTrace("Krabs-StopDispose-" + Guid.NewGuid().ToString("N")))
            {
                var provider = new Provider(TestTraceLoggingSource.ProviderGuid) { Any = 0 };
                trace.Enable(provider);

                for (int i = 0; i < 5; i++)
                {
                    trace.Open();
                    trace.Stop();
                }

                Assert.Equal(before + 1, TraceRegistry.InUse);
            }

            Assert.Equal(before, TraceRegistry.InUse);
        }

        /// <summary>
        /// Dispose releases the registration even when the caller never called Stop.
        /// </summary>
        [Fact]
        public void DisposeReleasesTheRegistrationWithoutAnExplicitStop()
        {
            int before = TraceRegistry.InUse;

            using (var trace = new UserTrace("Krabs-StopDispose-" + Guid.NewGuid().ToString("N")))
            {
                trace.Enable(new Provider(TestTraceLoggingSource.ProviderGuid) { Any = 0 });
                trace.Open();

                Assert.Equal(before + 1, TraceRegistry.InUse);
            }

            Assert.Equal(before, TraceRegistry.InUse);
        }
    }
}
