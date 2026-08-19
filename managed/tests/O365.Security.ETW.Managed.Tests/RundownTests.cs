using System;
using System.Threading;
using Xunit;

namespace Microsoft.O365.Security.ETW.Tests
{
    /// <summary>
    /// Covers rundown (CAPTURE_STATE), which asks a provider to describe state that already
    /// exists rather than state that changes while the trace runs.
    /// </summary>
    /// <remarks>
    /// krabs issues CAPTURE_STATE immediately before ProcessTrace and says why: any earlier
    /// and the rundown events are emitted with nothing consuming them. This library splits
    /// Open() and Start() into separate public calls, so "earlier" can mean arbitrarily
    /// earlier -- which is what this test reproduces by pausing between the two.
    ///
    /// Needs an elevated process, because starting a session does.
    /// </remarks>
    public class RundownTests
    {
        /// <summary>Microsoft-Windows-Kernel-Process.</summary>
        private static readonly Guid KernelProcessProviderId =
            Guid.Parse("22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716");

        private const ulong ProcessKeyword = 0x10;

        /// <summary>Kernel-Process emits ProcessRundown as event id 15.</summary>
        private const ushort ProcessRundownEventId = 15;

        [Fact]
        public void RundownEventsArriveEvenWhenOpenAndStartAreFarApart()
        {
            var seen = new ManualResetEventSlim(false);

            var provider = new Provider(KernelProcessProviderId);
            provider.Any = ProcessKeyword;
            provider.EnableRundownEvents();
            provider.OnEventRef += (in EventRecordRef record) =>
            {
                if (record.Id == ProcessRundownEventId)
                {
                    seen.Set();
                }
            };

            using (var trace = new UserTrace("Krabs-Managed-Tests-" + Guid.NewGuid().ToString("N")))
            {
                trace.Enable(provider);
                trace.Open();

                // The gap a consumer is free to leave. Rundown must survive it.
                Thread.Sleep(TimeSpan.FromSeconds(2));

                var processing = new Thread(trace.Start) { IsBackground = true };
                processing.Start();

                try
                {
                    Assert.True(
                        seen.Wait(EtwHarness.Timeout, TestContext.Current.CancellationToken),
                        "No ProcessRundown event arrived within the timeout.");
                }
                finally
                {
                    trace.Stop();
                    processing.Join(EtwHarness.Timeout);
                }
            }
        }
    }
}
