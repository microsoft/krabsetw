using System;
using System.Runtime.CompilerServices;
using Xunit;

namespace Microsoft.O365.Security.ETW.Tests
{
    /// <summary>
    /// Covers the one static in the library, and the reference cycle it used to make
    /// permanent.
    /// </summary>
    /// <remarks>
    /// ETW hands back an opaque context on every event, so a trace has to be findable from a
    /// static table. Holding those entries strongly rooted far more than the entry: a trace
    /// context reaches the providers enabled on it, which reach the consumer's handlers, which
    /// routinely close over the trace itself. The trace therefore stayed reachable, so its
    /// finalizer never ran, so it never unregistered — a cycle nothing could break for the
    /// life of the process, taking the consumer's whole object graph with it.
    /// </remarks>
    [Collection("etw")]
    public class TraceRegistryLifetimeTests
    {
        private sealed class Canary
        {
            public readonly byte[] Payload = new byte[4096];
        }

        private static void Collect()
        {
            GC.Collect();
            GC.WaitForPendingFinalizers();
            GC.Collect();
            GC.WaitForPendingFinalizers();
            GC.Collect();
        }

        /// <summary>
        /// The handler captures the trace, which is ordinary consumer code — stopping from a
        /// handler, re-enabling a provider, reading stats. That is what closes the cycle.
        /// </summary>
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static WeakReference AbandonTraceCapturedByItsOwnHandler()
        {
            var canary = new Canary();
            var trace = new UserTrace("Krabs-Registry-" + Guid.NewGuid().ToString("N"));
            var provider = new Provider(TestTraceLoggingSource.ProviderGuid) { Any = 0 };

            provider.OnEvent += record =>
            {
                GC.KeepAlive(canary);
                trace.Stop();
            };

            trace.Enable(provider);
            trace.Open();

            return new WeakReference(canary);
        }

        [Fact]
        public void ATraceCapturedByItsOwnHandlerIsStillCollected()
        {
            Collect();
            int before = TraceRegistry.InUse;

            WeakReference canary = AbandonTraceCapturedByItsOwnHandler();

            Collect();

            Assert.False(
                canary.IsAlive,
                "The consumer's object graph is still rooted by the trace registry.");

            Assert.Equal(before, TraceRegistry.InUse);
        }

        /// <summary>
        /// The plain case, for contrast: no cycle, and it has to keep working.
        /// </summary>
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static WeakReference AbandonTraceWithoutCapture()
        {
            var canary = new Canary();
            var trace = new UserTrace("Krabs-Registry-" + Guid.NewGuid().ToString("N"));
            var provider = new Provider(TestTraceLoggingSource.ProviderGuid) { Any = 0 };

            provider.OnEvent += record => GC.KeepAlive(canary);

            trace.Enable(provider);
            trace.Open();

            return new WeakReference(canary);
        }

        [Fact]
        public void AnAbandonedTraceIsCollected()
        {
            Collect();
            int before = TraceRegistry.InUse;

            WeakReference canary = AbandonTraceWithoutCapture();

            Collect();

            Assert.False(canary.IsAlive, "The consumer's handler was not collected.");
            Assert.Equal(before, TraceRegistry.InUse);
        }

        /// <summary>
        /// A registered trace must stay resolvable while it is in use, which is the thing the
        /// weak reference could plausibly break.
        /// </summary>
        [Fact]
        public void AliveTracesStayResolvableAcrossCollections()
        {
            using (var trace = new UserTrace("Krabs-Registry-" + Guid.NewGuid().ToString("N")))
            {
                trace.Enable(new Provider(TestTraceLoggingSource.ProviderGuid) { Any = 0 });
                trace.Open();

                int registered = TraceRegistry.InUse;

                Collect();

                Assert.Equal(registered, TraceRegistry.InUse);
            }
        }
    }
}
