using System;
using Microsoft.O365.Security.ETW.Kernel;
using Xunit;

namespace Microsoft.O365.Security.ETW.Tests
{
    /// <summary>
    /// Covers kernel providers that have no EVENT_TRACE_FLAG_ bit and are instead turned on
    /// through a PERFINFO group mask.
    /// </summary>
    /// <remarks>
    /// The group mask is applied through NtQuerySystemInformation/NtSetSystemInformation with
    /// an EVENT_TRACE_INFORMATION_CLASS sub-class. That enum is undocumented, absent from the
    /// SDK headers, and its members are only ever referred to by name in krabs, so a wrong
    /// numeric value cannot be caught by a layout assertion -- only by asking the kernel.
    ///
    /// Needs an elevated process, because starting a system logger does.
    /// </remarks>
    [Collection("etw")]
    public class KernelGroupMaskTests
    {
        [Fact]
        public void AGroupMaskProviderCanBeEnabled()
        {
            using (var trace = new KernelTrace("Krabs-Managed-Tests-" + Guid.NewGuid().ToString("N")))
            {
                var provider = new ObjectManagerProvider();
                provider.OnEvent += _ => { };
                trace.Enable(provider);

                // Open() is where the group mask is applied; a bad information class makes the
                // kernel reject it and Open() throws.
                trace.Open();
                trace.Stop();
            }
        }
    }
}
