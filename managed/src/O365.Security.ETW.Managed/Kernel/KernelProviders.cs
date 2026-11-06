using System;

namespace Microsoft.O365.Security.ETW.Kernel
{
    /// <summary>
    /// GUIDs the NT kernel logger stamps on its events. Port of krabs::guids.
    /// </summary>
    internal static class KernelGuids
    {
        public static readonly Guid Alpc = new Guid("45d8cccd-539f-4b72-a8b7-5c683142609a");
        public static readonly Guid Debug = new Guid("13976d09-a327-438c-950b-7f03192815c7");
        public static readonly Guid DiskIo = new Guid("3d6fa8d4-fe05-11d0-9dda-00c04fd7ba7c");
        public static readonly Guid EventTraceConfig = new Guid("01853a65-418f-4f36-aefc-dc0f1d2fd235");
        public static readonly Guid FileIo = new Guid("90cbdc39-4a3e-11d1-84f4-0000f80464e3");
        public static readonly Guid ImageLoad = new Guid("2cb15d1d-5fc1-11d2-abe1-00a0c911f518");
        public static readonly Guid PageFault = new Guid("3d6fa8d3-fe05-11d0-9dda-00c04fd7ba7c");
        public static readonly Guid PerfInfo = new Guid("ce1dbfb4-137e-4da6-87b0-3f59aa102cbc");
        public static readonly Guid Process = new Guid("3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c");
        public static readonly Guid Registry = new Guid("ae53722e-c863-11d2-8659-00c04fa321a1");
        public static readonly Guid SplitIo = new Guid("d837ca92-12b9-44a5-ad6a-3a65b3578aa8");
        public static readonly Guid TcpIp = new Guid("9a280ac0-c8e0-11d1-84e2-00c04fb998a2");
        public static readonly Guid Thread = new Guid("3d6fa8d1-fe05-11d0-9dda-00c04fd7ba7c");
        public static readonly Guid UdpIp = new Guid("bf3a50c5-a9c9-4988-a005-2df0b7c80f80");
        public static readonly Guid SystemTrace = new Guid("9e814aad-3204-11d2-9a82-006008a86939");
        public static readonly Guid ObTrace = new Guid("89497f50-effe-4440-8cf2-ce6b1cdcaca7");
        public static readonly Guid PoolTrace = new Guid("0268a8b6-74fd-4302-9dd0-6e8f1795c0cf");
        public static readonly Guid EventTrace = new Guid("68fdd900-4a3e-11d1-84f4-0000f80464e3");
        public static readonly Guid LostEvent = new Guid("6a399ae0-4bc6-4de9-870b-3657f8947e7e");
        public static readonly Guid UmsEvent = new Guid("9aec974b-5b8e-4118-9b92-3186d8002ce5");
        public static readonly Guid StackWalk = new Guid("def2fe46-7bd6-4b80-bd94-f57fe20d0ce3");
        public static readonly Guid Power = new Guid("e43445e0-0903-48c3-b878-ff0fccebdd04");
        public static readonly Guid MmcssTrace = new Guid("f8f10121-b617-4a56-868b-9df1b27fe32c");
        public static readonly Guid Rundown = new Guid("3b9c9951-3480-4220-9377-9c8e5184f5cd");
    }

    /// <summary>EVENT_TRACE_FLAG_* values from evntrace.h.</summary>
    internal static class KernelTraceFlags
    {
        public const uint Process = 0x00000001;
        public const uint Thread = 0x00000002;
        public const uint ImageLoad = 0x00000004;
        public const uint ProcessCounters = 0x00000008;
        public const uint Cswitch = 0x00000010;
        public const uint Dpc = 0x00000020;
        public const uint Interrupt = 0x00000040;
        public const uint Systemcall = 0x00000080;
        public const uint DiskIo = 0x00000100;
        public const uint DiskFileIo = 0x00000200;
        public const uint DiskIoInit = 0x00000400;
        public const uint Dispatcher = 0x00000800;
        public const uint MemoryPageFaults = 0x00001000;
        public const uint MemoryHardFaults = 0x00002000;
        public const uint VirtualAlloc = 0x00004000;
        public const uint Vamap = 0x00008000;
        public const uint NetworkTcpip = 0x00010000;
        public const uint Registry = 0x00020000;
        public const uint Dbgprint = 0x00040000;
        public const uint Alpc = 0x00100000;
        public const uint SplitIo = 0x00200000;
        public const uint Driver = 0x00800000;
        public const uint Profile = 0x01000000;
        public const uint FileIo = 0x02000000;
        public const uint FileIoInit = 0x04000000;
    }

    /// <summary>PERFINFO group masks from perfinfo_groupmask.hpp.</summary>
    internal static class PerfInfoGroupMask
    {
        public const uint ObHandle = 0x80000040;
    }

    /// <summary>A provider that enables ALPC events.</summary>
    public sealed class AlpcProvider : KernelProvider
    {
        public AlpcProvider() : base(KernelTraceFlags.Alpc, KernelGuids.Alpc) { }
    }

    /// <summary>A provider that enables context switch events.</summary>
    public sealed class ContextSwitchProvider : KernelProvider
    {
        public ContextSwitchProvider() : base(KernelTraceFlags.Cswitch, KernelGuids.Thread) { }
    }

    /// <summary>A provider that enables debug print events.</summary>
    public sealed class DebugPrintProvider : KernelProvider
    {
        public DebugPrintProvider() : base(KernelTraceFlags.Dbgprint, KernelGuids.Debug) { }
    }

    /// <summary>A provider that enables file I/O name events.</summary>
    public sealed class DiskFileIoProvider : KernelProvider
    {
        public DiskFileIoProvider() : base(KernelTraceFlags.DiskFileIo, KernelGuids.FileIo) { }
    }

    /// <summary>A provider that enables disk I/O completion events.</summary>
    public sealed class DiskIoProvider : KernelProvider
    {
        public DiskIoProvider() : base(KernelTraceFlags.DiskIo, KernelGuids.DiskIo) { }
    }

    /// <summary>A provider that enables beginning of disk I/O events.</summary>
    public sealed class DiskInitIoProvider : KernelProvider
    {
        public DiskInitIoProvider() : base(KernelTraceFlags.DiskIoInit, KernelGuids.DiskIo) { }
    }

    /// <summary>A provider that enables file I/O completion events.</summary>
    public sealed class FileIoProvider : KernelProvider
    {
        public FileIoProvider() : base(KernelTraceFlags.FileIo, KernelGuids.FileIo) { }
    }

    /// <summary>A provider that enables file I/O events.</summary>
    public sealed class FileInitIoProvider : KernelProvider
    {
        public FileInitIoProvider() : base(KernelTraceFlags.FileIoInit, KernelGuids.FileIo) { }
    }

    /// <summary>A provider that enables thread dispatch events.</summary>
    public sealed class ThreadDispatchProvider : KernelProvider
    {
        public ThreadDispatchProvider() : base(KernelTraceFlags.Dispatcher, KernelGuids.Thread) { }
    }

    /// <summary>A provider that enables device deferred procedure call events.</summary>
    public sealed class DpcProvider : KernelProvider
    {
        public DpcProvider() : base(KernelTraceFlags.Dpc, KernelGuids.PerfInfo) { }
    }

    /// <summary>A provider that enables driver events.</summary>
    public sealed class DriverProvider : KernelProvider
    {
        public DriverProvider() : base(KernelTraceFlags.Driver, KernelGuids.DiskIo) { }
    }

    /// <summary>A provider that enables image load events.</summary>
    public sealed class ImageLoadProvider : KernelProvider
    {
        public ImageLoadProvider() : base(KernelTraceFlags.ImageLoad, KernelGuids.ImageLoad) { }
    }

    /// <summary>A provider that enables interrupt events.</summary>
    public sealed class InterruptProvider : KernelProvider
    {
        public InterruptProvider() : base(KernelTraceFlags.Interrupt, KernelGuids.PerfInfo) { }
    }

    /// <summary>A provider that enables memory hard fault events.</summary>
    public sealed class MemoryHardFaultProvider : KernelProvider
    {
        public MemoryHardFaultProvider() : base(KernelTraceFlags.MemoryHardFaults, KernelGuids.PageFault) { }
    }

    /// <summary>A provider that enables memory page fault events.</summary>
    public sealed class MemoryPageFaultProvider : KernelProvider
    {
        public MemoryPageFaultProvider() : base(KernelTraceFlags.MemoryPageFaults, KernelGuids.PageFault) { }
    }

    /// <summary>A provider that enables network tcp/ip events.</summary>
    public sealed class NetworkTcpipProvider : KernelProvider
    {
        public NetworkTcpipProvider() : base(KernelTraceFlags.NetworkTcpip, KernelGuids.TcpIp) { }
    }

    /// <summary>A provider that enables process events.</summary>
    public sealed class ProcessProvider : KernelProvider
    {
        public ProcessProvider() : base(KernelTraceFlags.Process, KernelGuids.Process) { }
    }

    /// <summary>A provider that enables process counter events.</summary>
    public sealed class ProcessCounterProvider : KernelProvider
    {
        public ProcessCounterProvider() : base(KernelTraceFlags.ProcessCounters, KernelGuids.Process) { }
    }

    /// <summary>A provider that enables profiling events.</summary>
    public sealed class ProfileProvider : KernelProvider
    {
        public ProfileProvider() : base(KernelTraceFlags.Profile, KernelGuids.PerfInfo) { }
    }

    /// <summary>A provider that enables registry events.</summary>
    public sealed class RegistryProvider : KernelProvider
    {
        public RegistryProvider() : base(KernelTraceFlags.Registry, KernelGuids.Registry) { }
    }

    /// <summary>A provider that enables split I/O events.</summary>
    public sealed class SplitIoProvider : KernelProvider
    {
        public SplitIoProvider() : base(KernelTraceFlags.SplitIo, KernelGuids.SplitIo) { }
    }

    /// <summary>A provider that enables system call events.</summary>
    /// <remarks>
    /// Uses PerfInfo, as native krabs does, rather than the SystemTrace GUID the C++/CLI
    /// wrapper carries. SysCall enter and exit events are stamped with the PerfInfo GUID,
    /// and kernel events route on the header GUID alone, so a SystemTrace provider enables
    /// the flag and then matches nothing. Native krabs fixed this in 7e2dc32 ("guid for
    /// system_call_provider should be PerfInfo not SystemTraceControl"); the wrapper was
    /// updated afterwards, in 396d8cc, but picked up only that commit's new providers and
    /// not the fix. This is the one place the port deliberately declines to reproduce the
    /// wrapper, because reproducing it means the provider cannot work.
    /// </remarks>
    public sealed class SystemCallProvider : KernelProvider
    {
        public SystemCallProvider() : base(KernelTraceFlags.Systemcall, KernelGuids.PerfInfo) { }
    }

    /// <summary>A provider that enables thread start and stop events.</summary>
    public sealed class ThreadProvider : KernelProvider
    {
        public ThreadProvider() : base(KernelTraceFlags.Thread, KernelGuids.Thread) { }
    }

    /// <summary>A provider that enables file map and unmap (excluding images) events.</summary>
    public sealed class VaMapProvider : KernelProvider
    {
        public VaMapProvider() : base(KernelTraceFlags.Vamap, KernelGuids.FileIo) { }
    }

    /// <summary>A provider that enables VirtualAlloc and VirtualFree events.</summary>
    public sealed class VirtualAllocProvider : KernelProvider
    {
        public VirtualAllocProvider() : base(KernelTraceFlags.VirtualAlloc, KernelGuids.PageFault) { }
    }

    /// <summary>A provider that enables Object Manager events.</summary>
    public sealed class ObjectManagerProvider : KernelProvider
    {
        public ObjectManagerProvider() : base(KernelGuids.ObTrace, PerfInfoGroupMask.ObHandle) { }
    }
}
