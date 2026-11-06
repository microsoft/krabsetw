using System;
using System.Collections.Generic;
using Microsoft.O365.Security.ETW.Kernel;
using Xunit;

namespace Microsoft.O365.Security.ETW.Tests
{
    /// <summary>
    /// Verifies the managed kernel convenience-provider table against the native krabs
    /// headers, except for compatibility cases called out explicitly.
    /// </summary>
    public class KernelProviderTableTests
    {
        public static IEnumerable<object[]> Providers()
        {
            yield return Row(typeof(AlpcProvider), 0x00100000u, Guid.Parse("45d8cccd-539f-4b72-a8b7-5c683142609a"));
            yield return Row(typeof(ContextSwitchProvider), 0x00000010u, Guid.Parse("3d6fa8d1-fe05-11d0-9dda-00c04fd7ba7c"));
            yield return Row(typeof(DebugPrintProvider), 0x00040000u, Guid.Parse("13976d09-a327-438c-950b-7f03192815c7"));
            yield return Row(typeof(DiskFileIoProvider), 0x00000200u, Guid.Parse("90cbdc39-4a3e-11d1-84f4-0000f80464e3"));
            yield return Row(typeof(DiskIoProvider), 0x00000100u, Guid.Parse("3d6fa8d4-fe05-11d0-9dda-00c04fd7ba7c"));
            yield return Row(typeof(DiskInitIoProvider), 0x00000400u, Guid.Parse("3d6fa8d4-fe05-11d0-9dda-00c04fd7ba7c"));
            yield return Row(typeof(FileIoProvider), 0x02000000u, Guid.Parse("90cbdc39-4a3e-11d1-84f4-0000f80464e3"));
            yield return Row(typeof(FileInitIoProvider), 0x04000000u, Guid.Parse("90cbdc39-4a3e-11d1-84f4-0000f80464e3"));
            yield return Row(typeof(ThreadDispatchProvider), 0x00000800u, Guid.Parse("3d6fa8d1-fe05-11d0-9dda-00c04fd7ba7c"));
            yield return Row(typeof(DpcProvider), 0x00000020u, Guid.Parse("ce1dbfb4-137e-4da6-87b0-3f59aa102cbc"));
            yield return Row(typeof(DriverProvider), 0x00800000u, Guid.Parse("3d6fa8d4-fe05-11d0-9dda-00c04fd7ba7c"));
            yield return Row(typeof(ImageLoadProvider), 0x00000004u, Guid.Parse("2cb15d1d-5fc1-11d2-abe1-00a0c911f518"));
            yield return Row(typeof(InterruptProvider), 0x00000040u, Guid.Parse("ce1dbfb4-137e-4da6-87b0-3f59aa102cbc"));
            yield return Row(typeof(MemoryHardFaultProvider), 0x00002000u, Guid.Parse("3d6fa8d3-fe05-11d0-9dda-00c04fd7ba7c"));
            yield return Row(typeof(MemoryPageFaultProvider), 0x00001000u, Guid.Parse("3d6fa8d3-fe05-11d0-9dda-00c04fd7ba7c"));
            yield return Row(typeof(NetworkTcpipProvider), 0x00010000u, Guid.Parse("9a280ac0-c8e0-11d1-84e2-00c04fb998a2"));
            yield return Row(typeof(ProcessProvider), 0x00000001u, Guid.Parse("3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c"));
            yield return Row(typeof(ProcessCounterProvider), 0x00000008u, Guid.Parse("3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c"));
            yield return Row(typeof(ProfileProvider), 0x01000000u, Guid.Parse("ce1dbfb4-137e-4da6-87b0-3f59aa102cbc"));
            yield return Row(typeof(RegistryProvider), 0x00020000u, Guid.Parse("ae53722e-c863-11d2-8659-00c04fa321a1"));
            yield return Row(typeof(SplitIoProvider), 0x00200000u, Guid.Parse("d837ca92-12b9-44a5-ad6a-3a65b3578aa8"));
            yield return Row(typeof(ThreadProvider), 0x00000002u, Guid.Parse("3d6fa8d1-fe05-11d0-9dda-00c04fd7ba7c"));
            yield return Row(typeof(VaMapProvider), 0x00008000u, Guid.Parse("90cbdc39-4a3e-11d1-84f4-0000f80464e3"));
            yield return Row(typeof(VirtualAllocProvider), 0x00004000u, Guid.Parse("3d6fa8d3-fe05-11d0-9dda-00c04fd7ba7c"));
        }

        [Theory]
        [MemberData(nameof(Providers))]
        public void ConvenienceProvidersMatchNativeKrabsHeaders(Type providerType, uint flags, Guid id)
        {
            var provider = Assert.IsAssignableFrom<KernelProvider>(Activator.CreateInstance(providerType));

            Assert.Equal(flags, provider.Flags);
            Assert.Equal(id, provider.Id);
            Assert.Equal(0u, provider.GroupMask);
        }

        [Fact]
        public void ObjectManagerProviderMatchesNativeKrabsGroupMaskProvider()
        {
            var provider = new ObjectManagerProvider();

            Assert.Equal(Guid.Parse("89497f50-effe-4440-8cf2-ce6b1cdcaca7"), provider.Id);
            Assert.Equal(0u, provider.Flags);
            Assert.Equal(0x80000040u, provider.GroupMask);
        }

        [Fact]
        public void SystemCallProviderMatchesNativeKrabsRatherThanTheCppCliWrapper()
        {
            var provider = new SystemCallProvider();

            // The one place the port deliberately declines to reproduce the C++/CLI wrapper.
            // Native krabs uses perf_info, which is the GUID stamped on SysCall enter and
            // exit events; the wrapper carries system_trace (9e814aad-...), which is the NT
            // Kernel Logger's session control GUID and appears on no event record. Since
            // kernel events route on the header GUID alone, the wrapper's provider enables
            // the SysCall flag and then matches nothing. Native fixed this in 7e2dc32; the
            // wrapper was edited afterwards in 396d8cc and took only that commit's new
            // providers, not the fix.
            Assert.Equal(0x00000080u, provider.Flags);
            Assert.Equal(Guid.Parse("ce1dbfb4-137e-4da6-87b0-3f59aa102cbc"), provider.Id);
            Assert.NotEqual(Guid.Parse("9e814aad-3204-11d2-9a82-006008a86939"), provider.Id);
        }

        private static object[] Row(Type providerType, uint flags, Guid id)
        {
            return new object[] { providerType, flags, id };
        }
    }
}
