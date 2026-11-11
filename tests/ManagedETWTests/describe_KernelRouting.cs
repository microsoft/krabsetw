// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.O365.Security.ETW;
using Microsoft.O365.Security.ETW.Kernel;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace EtwTestsCS
{
    [TestClass]
    public class describe_KernelRouting
    {
        [TestMethod]
        public void system_call_provider_receives_system_calls()
        {
            var provider = new SystemCallProvider();
            using (var received = new ManualResetEventSlim())
            using (var trace = new KernelTrace("krabs-syscall-" + Guid.NewGuid()))
            using ((object)provider as IDisposable)
            {
                // Syscall records can carry an unknown PID; this test observes system-wide tracing.
                provider.OnMetadata += e =>
                {
                    if (!received.IsSet)
                        received.Set();
                };
                trace.Enable(provider);
                trace.Open();
                var processing = Task.Run(() => trace.Start());
                bool observed;
                try
                {
                    for (int i = 0; i < 50 && !received.IsSet; i++)
                        Thread.Sleep(10);
                    observed = received.Wait(TimeSpan.FromSeconds(5));
                }
                finally
                {
                    trace.Stop();
                    Assert.IsTrue(processing.Wait(TimeSpan.FromSeconds(10)),
                        "Kernel processing did not stop.");
                }
                Assert.IsTrue(observed, "SystemCallProvider enabled tracing but received no syscall events.");
            }
        }
    }
}
