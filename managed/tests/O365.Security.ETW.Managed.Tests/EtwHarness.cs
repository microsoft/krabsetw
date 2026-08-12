using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.O365.Security.ETW.Tests
{
    /// <summary>
    /// Runs a real ETW session against a real provider until a signal fires or a deadline
    /// passes. Needs an elevated process, because creating a session does.
    /// </summary>
    internal static class EtwHarness
    {
        public static readonly TimeSpan Timeout = TimeSpan.FromSeconds(30);

        /// <summary>
        /// Matches only events emitted by the process running the test.
        /// </summary>
        /// <remarks>
        /// The test provider is an EventSource whose GUID is derived from its name, so every
        /// test process -- one per target framework, run concurrently -- registers the same
        /// provider. A session in one of them therefore receives the others' events, which
        /// makes any assertion that counts events or reads their payload depend on what a
        /// sibling process happens to be doing. Scoping to this process removes that.
        /// </remarks>
        public static readonly Predicate ThisProcess =
            Filter.ProcessIdIs(Process.GetCurrentProcess().Id);

        /// <summary>
        /// How long to keep emitting when the signal is never expected to fire. Long enough
        /// for the session to be delivering events, short enough not to dominate the suite.
        /// </summary>
        public static readonly TimeSpan NegativeTimeout = TimeSpan.FromSeconds(3);

        public static void Run(Provider provider, ManualResetEventSlim signal, Action emit)
        {
            Run(provider, signal, emit, Timeout);
        }

        public static void Run(Provider provider, ManualResetEventSlim signal, Action emit, TimeSpan timeout)
        {
            using (var trace = new UserTrace("Krabs-Managed-Tests-" + Guid.NewGuid().ToString("N")))
            {
                trace.Enable(provider);
                trace.Open();

                Task processing = Task.Run(() => trace.Start());

                try
                {
                    var deadline = DateTime.UtcNow + timeout;

                    while (DateTime.UtcNow < deadline && !signal.IsSet)
                    {
                        emit();
                        signal.Wait(TimeSpan.FromMilliseconds(250));
                    }
                }
                finally
                {
                    trace.Stop();
                    processing.Wait(Timeout);
                }
            }
        }
    }
}
