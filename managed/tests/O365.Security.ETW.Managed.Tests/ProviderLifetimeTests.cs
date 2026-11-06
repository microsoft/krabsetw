using System;
using System.Runtime.CompilerServices;
using Microsoft.O365.Security.ETW;
using Microsoft.O365.Security.ETW.Testing;
using Xunit;

namespace Microsoft.O365.Security.ETW.Tests
{
    /// <summary>
    /// A trace must keep the providers enabled on it alive.
    /// </summary>
    /// <remarks>
    /// Enabling a provider hands the trace the provider's event sinks. If that is all the
    /// trace retains, the managed <see cref="Provider"/> -- which owns the delegates --
    /// becomes unreachable as soon as the caller drops its reference, and the next collection
    /// silently stops event delivery.
    ///
    /// This is a realistic usage pattern: callers routinely build and enable a provider
    /// inside a helper method without holding on to it, on the reasonable assumption that the
    /// trace now owns it.
    /// </remarks>
    public class ProviderLifetimeTests
    {
        private static readonly Guid PowerShellProviderId = Guid.Parse("A0C1853B-5C40-4B15-8766-3CF1C58F985A");

        [Fact]
        public void ATraceStillDeliversEventsAfterACollection()
        {
            var trace = new UserTrace();
            var proxy = new Proxy(trace);
            bool called = false;

            EnableInSeparateScope(trace, () => called = true);
            Collect();

            using (SynthRecord record = Record())
            {
                proxy.PushEvent(record);
            }

            Assert.True(called, "the trace did not keep the enabled provider alive across a collection");
        }

        [Fact]
        public void ATraceStillAppliesFiltersAfterACollection()
        {
            var trace = new UserTrace();
            var proxy = new Proxy(trace);
            bool called = false;

            EnableFilteredInSeparateScope(trace, () => called = true);
            Collect();

            using (SynthRecord record = Record())
            {
                proxy.PushEvent(record);
            }

            Assert.True(called, "the trace did not keep the enabled provider's filter alive across a collection");
        }

        /// <summary>
        /// The provider is created and dropped inside a method that is never inlined, so it
        /// is genuinely unreachable by the time the collection runs.
        /// </summary>
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static void EnableInSeparateScope(UserTrace trace, Action onEvent)
        {
            var provider = new Provider(PowerShellProviderId);
            provider.OnEvent += e => onEvent();

            trace.Enable(provider);
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        private static void EnableFilteredInSeparateScope(UserTrace trace, Action onEvent)
        {
            var provider = new Provider(PowerShellProviderId);

            var filter = new EventFilter(Filter.AnyEvent());
            filter.OnEvent += e => onEvent();

            provider.AddFilter(filter);
            trace.Enable(provider);
        }

        private static SynthRecord Record()
        {
            using (var builder = new RecordBuilder(PowerShellProviderId, 7937, 1))
            {
                builder.AddUnicodeString("UserData", "user data");
                builder.AddUnicodeString("ContextInfo", "context info");
                builder.AddUnicodeString("Payload", "payload");

                return builder.Pack();
            }
        }

        private static void Collect()
        {
            GC.Collect();
            GC.WaitForPendingFinalizers();
            GC.Collect();
        }
    }
}
