// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Runtime.CompilerServices;
using Microsoft.VisualStudio.TestTools.UnitTesting;

using Microsoft.O365.Security.ETW;
using Microsoft.O365.Security.ETW.Testing;

namespace EtwTestsCS
{
    using Events;

    /// <summary>
    /// A trace must keep the providers enabled on it alive.
    /// </summary>
    /// <remarks>
    /// Enabling a provider hands the trace the provider's native representation. If that is
    /// all the trace retains, the managed Provider object — which owns the event delegates —
    /// becomes unreachable as soon as the caller drops its reference, and the next
    /// collection silently stops event delivery.
    ///
    /// This is a realistic usage pattern: callers routinely build and enable a provider
    /// inside a helper method without holding on to it, on the reasonable assumption that
    /// the trace now owns it.
    /// </remarks>
    [TestClass]
    public class describe_ProviderLifetime
    {
        [TestMethod]
        public void it_should_still_deliver_events_after_a_collection()
        {
            var called = false;

            var trace = new UserTrace();
            var proxy = new Proxy(trace);

            EnableInSeparateScope(trace, () => called = true);
            Collect();

            proxy.PushEvent(PowerShellEvent.CreateRecord("user data", "context info", "payload"));

            Assert.IsTrue(
                called,
                "the trace did not keep the enabled provider alive across a collection");
        }

        [TestMethod]
        public void it_should_still_apply_filters_after_a_collection()
        {
            var called = false;

            var trace = new UserTrace();
            var proxy = new Proxy(trace);

            EnableFilteredInSeparateScope(trace, () => called = true);
            Collect();

            proxy.PushEvent(PowerShellEvent.CreateRecord("user data", "context info", "payload"));

            Assert.IsTrue(
                called,
                "the trace did not keep the enabled provider's filter alive across a collection");
        }

        /// <summary>
        /// The provider is created and dropped inside a method that is never inlined, so it
        /// is genuinely unreachable by the time the collection runs.
        /// </summary>
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static void EnableInSeparateScope(UserTrace trace, Action onEvent)
        {
            var provider = new Provider(PowerShellEvent.ProviderId);
            provider.OnEvent += e => onEvent();

            trace.Enable(provider);
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        private static void EnableFilteredInSeparateScope(UserTrace trace, Action onEvent)
        {
            var provider = new Provider(PowerShellEvent.ProviderId);

            var filter = new EventFilter(Filter.AnyEvent());
            filter.OnEvent += e => onEvent();

            provider.AddFilter(filter);
            trace.Enable(provider);
        }

        private static void Collect()
        {
            GC.Collect();
            GC.WaitForPendingFinalizers();
            GC.Collect();
        }
    }
}
