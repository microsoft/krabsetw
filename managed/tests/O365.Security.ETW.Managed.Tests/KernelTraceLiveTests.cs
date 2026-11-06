using System;
using System.Threading;
using Microsoft.O365.Security.ETW.Kernel;
using Xunit;

namespace Microsoft.O365.Security.ETW.Tests
{
    /// <summary>
    /// Covers kernel-trace paths that only ETW can drive: starting the system logger,
    /// processing in ProcessTrace, and querying live session counters.
    /// </summary>
    /// <remarks>
    /// These need elevation for the same reason as <see cref="KernelGroupMaskTests"/>:
    /// starting a system logger is an administrative operation.
    /// </remarks>
    [Collection("etw")]
    public class KernelTraceLiveTests
    {
        [Fact]
        public void StartedTraceCanBeQueriedAndStopped()
        {
            using (var trace = new KernelTrace("Krabs-Managed-Tests-" + Guid.NewGuid().ToString("N")))
            {
                trace.Enable(new ProcessProvider());

                Exception processingError = null;
                var processing = new Thread(() => CaptureStart(trace, ref processingError))
                {
                    IsBackground = true
                };
                processing.Start();

                try
                {
                    TraceStats stats = WaitForQueryableStats(trace);

                    Assert.True(stats.BuffersCount > 0);
                    Assert.True(stats.BuffersFree <= stats.BuffersCount);
                    Assert.Equal(stats.EventsHandled + stats.EventsLost, stats.EventsTotal);
                    Assert.Equal(trace.UnhandledExceptions, stats.UnhandledExceptions);
                }
                finally
                {
                    trace.Stop();
                    Assert.True(processing.Join(EtwHarness.Timeout), "Kernel processing did not stop.");
                }

                Assert.Null(processingError);
            }
        }

        [Fact]
        public void StartRejectsASecondConcurrentProcessor()
        {
            using (var trace = new KernelTrace("Krabs-Managed-Tests-" + Guid.NewGuid().ToString("N")))
            {
                trace.Enable(new ProcessProvider());

                Exception processingError = null;
                var processing = new Thread(() => CaptureStart(trace, ref processingError))
                {
                    IsBackground = true
                };
                processing.Start();

                try
                {
                    WaitForProcessingStarted(trace, () => Volatile.Read(ref processingError));

                    InvalidOperationException ex = Assert.Throws<InvalidOperationException>(() => trace.Start());
                    Assert.Contains("already processing events", ex.Message, StringComparison.Ordinal);
                }
                finally
                {
                    trace.Stop();
                    Assert.True(processing.Join(EtwHarness.Timeout), "Kernel processing did not stop.");
                }

                Assert.Null(processingError);
            }
        }

        [Fact]
        public void EnableAfterOpenIsRejected()
        {
            using (var trace = new KernelTrace("Krabs-Managed-Tests-" + Guid.NewGuid().ToString("N")))
            {
                trace.Enable(new ProcessProvider());
                trace.Open();

                try
                {
                    InvalidOperationException ex = Assert.Throws<InvalidOperationException>(
                        () => trace.Enable(new ThreadProvider()));

                    Assert.Contains("before the trace is opened", ex.Message, StringComparison.Ordinal);
                }
                finally
                {
                    trace.Stop();
                }
            }
        }

        private static void CaptureStart(KernelTrace trace, ref Exception error)
        {
            try
            {
                trace.Start();
            }
            catch (Exception ex)
            {
                Volatile.Write(ref error, ex);
            }
        }

        private static void WaitForProcessingStarted(KernelTrace trace, Func<Exception> getError)
        {
            var deadline = DateTime.UtcNow + EtwHarness.Timeout;

            while (DateTime.UtcNow < deadline)
            {
                Exception error = getError();
                if (error != null)
                {
                    throw new InvalidOperationException("Kernel processing failed before it started.", error);
                }

                if (trace.BuffersProcessed > 0)
                {
                    return;
                }

                Thread.Sleep(TimeSpan.FromMilliseconds(100));
            }

            throw new TimeoutException("The kernel trace did not start processing buffers.");
        }

        private static TraceStats WaitForQueryableStats(KernelTrace trace)
        {
            Exception last = null;
            var deadline = DateTime.UtcNow + EtwHarness.Timeout;

            while (DateTime.UtcNow < deadline)
            {
                try
                {
                    return trace.QueryStats();
                }
                catch (TraceException ex)
                {
                    last = ex;
                    Thread.Sleep(TimeSpan.FromMilliseconds(100));
                }
            }

            throw new TimeoutException("The kernel trace did not become queryable.", last);
        }
    }
}




