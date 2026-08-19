using System;
using System.Threading;
using Xunit;

namespace Microsoft.O365.Security.ETW.Tests
{
    /// <summary>
    /// Covers a throwing handler against a real session, which is the only place the
    /// mechanism can actually be exercised: the synthetic proxy cannot stop ProcessTrace,
    /// and stopping it from inside its own callback is the load-bearing part.
    /// </summary>
    [Collection("etw")]
    public class HandlerExceptionLiveTests
    {
        /// <summary>
        /// The behaviour a krabs or C++/CLI consumer already depends on: a handler that
        /// throws brings the trace down and the exception comes out of Start, on the thread
        /// that called it, rather than being lost inside an ETW callback.
        /// </summary>
        [Fact]
        public void AThrowingHandlerStopsTheTraceAndRethrowsOutOfStart()
        {
            var provider = new Provider(TestTraceLoggingSource.ProviderGuid) { Any = 0 };

            using (var trace = new UserTrace("Krabs-HandlerEx-" + Guid.NewGuid().ToString("N")))
            {
                var filter = new EventFilter(EtwHarness.ThisProcess);
                filter.OnEvent += record => throw new InvalidOperationException("handler failed");

                IEventRecordException providerReport = null;
                IEventRecordException traceReport = null;

                provider.AddFilter(filter);
                provider.OnUnhandledException += e => providerReport = e;
                trace.DefaultUnhandledException = e => traceReport = e;

                trace.Enable(provider);
                trace.Open();

                Exception thrown = null;
                var processing = new Thread(() =>
                {
                    try
                    {
                        trace.Start();
                    }
                    catch (Exception ex)
                    {
                        thrown = ex;
                    }
                })
                { IsBackground = true };

                processing.Start();

                var emitting = new Thread(() =>
                {
                    while (thrown == null)
                    {
                        TestTraceLoggingSource.Log.Interesting("a", 1);
                        Thread.Sleep(50);
                    }
                })
                { IsBackground = true };

                emitting.Start();

                try
                {
                    // Start returning at all is the first half of the assertion: nothing else
                    // stops this trace, so it stopped itself from inside the callback.
                    Assert.True(
                        processing.Join(TimeSpan.FromSeconds(30)),
                        "Start never returned, so the handler exception did not stop the trace.");

                    Assert.NotNull(thrown);
                    Assert.IsType<InvalidOperationException>(thrown);
                    Assert.Equal("handler failed", thrown.Message);

                    // The original throw site, not the rethrow point: ExceptionDispatchInfo
                    // is what preserves it, and losing it would make the report useless.
                    Assert.Contains(nameof(AThrowingHandlerStopsTheTraceAndRethrowsOutOfStart), thrown.StackTrace);

                    Assert.NotNull(providerReport);
                    Assert.NotNull(traceReport);
                    Assert.True(providerReport.Stopping);
                    Assert.True(trace.UnhandledExceptions >= 1);
                }
                finally
                {
                    trace.Stop();
                    emitting.Join(TimeSpan.FromSeconds(10));
                    processing.Join(TimeSpan.FromSeconds(30));
                }
            }
        }

        /// <summary>
        /// With the option off the session survives, which is the whole point of having it:
        /// the counter and the reports are then the only evidence, so they have to work.
        /// </summary>
        [Fact]
        public void WithTheOptionOffTheTraceKeepsRunning()
        {
            var provider = new Provider(TestTraceLoggingSource.ProviderGuid) { Any = 0 };

            using (var reported = new ManualResetEventSlim(false))
            using (var trace = new UserTrace("Krabs-HandlerEx-" + Guid.NewGuid().ToString("N")))
            {
                var filter = new EventFilter(EtwHarness.ThisProcess);
                filter.OnEvent += record => throw new InvalidOperationException("handler failed");

                int reports = 0;

                provider.AddFilter(filter);
                trace.StopOnHandlerException = false;
                trace.DefaultUnhandledException = e =>
                {
                    if (Interlocked.Increment(ref reports) >= 3)
                    {
                        reported.Set();
                    }
                };

                trace.Enable(provider);
                trace.Open();

                Exception thrown = null;
                var processing = new Thread(() =>
                {
                    try
                    {
                        trace.Start();
                    }
                    catch (Exception ex)
                    {
                        thrown = ex;
                    }
                })
                { IsBackground = true };

                processing.Start();

                var emitting = new Thread(() =>
                {
                    while (!reported.IsSet)
                    {
                        TestTraceLoggingSource.Log.Interesting("a", 1);
                        Thread.Sleep(50);
                    }
                })
                { IsBackground = true };

                emitting.Start();

                try
                {
                    // Repeated reports prove the trace went on dispatching after the first
                    // throw rather than quietly winding down.
                    Assert.True(
                        reported.Wait(TimeSpan.FromSeconds(30), TestContext.Current.CancellationToken),
                        "The trace stopped dispatching after a handler threw.");

                    Assert.Null(thrown);
                    Assert.True(trace.UnhandledExceptions >= 3);
                }
                finally
                {
                    trace.Stop();
                    emitting.Join(TimeSpan.FromSeconds(10));
                    processing.Join(TimeSpan.FromSeconds(30));
                }

                // Stopped on request rather than by the exception, so Start returned cleanly.
                Assert.Null(thrown);
            }
        }

        /// <summary>
        /// A trace that a handler brought down must be restartable. The stop flag and the
        /// captured exception both belong to one run, and left set they would make the next
        /// run deliver nothing and then rethrow a stale failure.
        /// </summary>
        [Fact]
        public void ATraceStoppedByAHandlerCanBeRestarted()
        {
            var provider = new Provider(TestTraceLoggingSource.ProviderGuid) { Any = 0 };
            bool shouldThrow = true;

            using (var delivered = new ManualResetEventSlim(false))
            using (var trace = new UserTrace("Krabs-HandlerEx-" + Guid.NewGuid().ToString("N")))
            {
                var filter = new EventFilter(EtwHarness.ThisProcess);
                filter.OnEvent += record =>
                {
                    if (shouldThrow)
                    {
                        throw new InvalidOperationException("handler failed");
                    }

                    delivered.Set();
                };

                provider.AddFilter(filter);
                trace.Enable(provider);

                Assert.Throws<InvalidOperationException>(() => RunUntilStopped(trace));

                // Second run, same trace, with the handler no longer throwing.
                shouldThrow = false;

                trace.Open();

                var processing = new Thread(trace.Start) { IsBackground = true };
                processing.Start();

                var emitting = new Thread(() =>
                {
                    while (!delivered.IsSet)
                    {
                        TestTraceLoggingSource.Log.Interesting("a", 1);
                        Thread.Sleep(50);
                    }
                })
                { IsBackground = true };

                emitting.Start();

                try
                {
                    Assert.True(
                        delivered.Wait(TimeSpan.FromSeconds(30), TestContext.Current.CancellationToken),
                        "The restarted trace delivered nothing, so it was born stopped.");
                }
                finally
                {
                    trace.Stop();
                    emitting.Join(TimeSpan.FromSeconds(10));
                    processing.Join(TimeSpan.FromSeconds(30));
                }
            }
        }

        /// <summary>
        /// Drives a trace until its own handler stops it, and surfaces what Start threw.
        /// </summary>
        private static void RunUntilStopped(UserTrace trace)
        {
            trace.Open();

            Exception thrown = null;
            var processing = new Thread(() =>
            {
                try
                {
                    trace.Start();
                }
                catch (Exception ex)
                {
                    thrown = ex;
                }
            })
            { IsBackground = true };

            processing.Start();

            var emitting = new Thread(() =>
            {
                while (thrown == null)
                {
                    TestTraceLoggingSource.Log.Interesting("a", 1);
                    Thread.Sleep(50);
                }
            })
            { IsBackground = true };

            emitting.Start();

            Assert.True(processing.Join(TimeSpan.FromSeconds(30)), "Start never returned.");
            emitting.Join(TimeSpan.FromSeconds(10));

            if (thrown != null)
            {
                throw thrown;
            }
        }
    }
}
