// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Runtime.CompilerServices;
using Microsoft.O365.Security.ETW;
using Microsoft.O365.Security.ETW.Testing;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace EtwTestsCS
{
    [TestClass]
    public class describe_ProviderLifetime
    {
        [TestMethod]
        public void trace_retains_provider_and_delivers_after_collection()
        {
            using (var trace = new UserTrace())
            {
                bool called = false;
                var provider = EnableProvider(trace, () => called = true);
                Collect();
                Assert.IsTrue(provider.IsAlive, "The trace lost its managed provider.");
                new Proxy(trace).PushEvent(Events.PowerShellEvent.CreateRecord("", "", ""));
                Assert.IsTrue(called);
                GC.KeepAlive(trace);
            }
        }

        [TestMethod]
        public void provider_retains_filter_and_delivers_after_collection()
        {
            var provider = new Provider(Events.PowerShellEvent.ProviderId);
            using (var trace = new UserTrace())
            using ((object)provider as IDisposable)
            {
                bool called = false;
                var filter = AddFilter(provider, () => called = true);
                trace.Enable(provider);
                Collect();
                Assert.IsTrue(filter.IsAlive, "The provider lost its managed filter.");
                new Proxy(trace).PushEvent(Events.PowerShellEvent.CreateRecord("", "", ""));
                Assert.IsTrue(called);
                GC.KeepAlive(provider);
            }
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        private static WeakReference EnableProvider(UserTrace trace, Action callback)
        {
            var provider = new Provider(Events.PowerShellEvent.ProviderId);
            provider.OnEvent += e => callback();
            trace.Enable(provider);
            return new WeakReference(provider);
        }

        [TestMethod]
        public void kernel_trace_retains_provider_and_filter()
        {
            using (var trace = new KernelTrace())
            {
                bool called = false;
                var owners = EnableKernelProvider(trace, () => called = true);
                Collect();
                Assert.IsTrue(owners[0].IsAlive, "The kernel trace lost its provider.");
                Assert.IsTrue(owners[1].IsAlive, "The kernel provider lost its filter.");
                new Proxy(trace).PushEvent(Events.PowerShellEvent.CreateRecord("", "", ""));
                Assert.IsTrue(called);
                GC.KeepAlive(trace);
            }
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        private static WeakReference[] EnableKernelProvider(KernelTrace trace, Action callback)
        {
            var provider = new KernelProvider(0, Events.PowerShellEvent.ProviderId);
            var filter = new EventFilter(Filter.AnyEvent());
            filter.OnEvent += e => callback();
            provider.AddFilter(filter);
            trace.Enable(provider);
            return new[] { new WeakReference(provider), new WeakReference(filter) };
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        private static WeakReference AddFilter(Provider provider, Action callback)
        {
            var filter = new EventFilter(Filter.AnyEvent());
            filter.OnEvent += e => callback();
            provider.AddFilter(filter);
            return new WeakReference(filter);
        }

        private static void Collect()
        {
            GC.Collect();
            GC.WaitForPendingFinalizers();
            GC.Collect();
        }
    }
}
