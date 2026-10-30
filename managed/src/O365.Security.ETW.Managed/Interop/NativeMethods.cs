using System;
using System.Runtime.InteropServices;

namespace Microsoft.O365.Security.ETW.Interop
{
    /// <summary>
    /// Raw P/Invoke surface. Signatures are deliberately pointer-only and blittable so the
    /// generated marshalling stubs stay trivial - nothing here should require a marshaller.
    /// </summary>
    internal static unsafe class NativeMethods
    {
        private const string Advapi32 = "advapi32.dll";
        private const string Tdh = "tdh.dll";

        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport(Advapi32, EntryPoint = "StartTraceW", CharSet = CharSet.Unicode, SetLastError = false)]
        public static extern int StartTrace(
            out ulong sessionHandle,
            [MarshalAs(UnmanagedType.LPWStr)] string sessionName,
            EVENT_TRACE_PROPERTIES* properties);

        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport(Advapi32, EntryPoint = "ControlTraceW", CharSet = CharSet.Unicode, SetLastError = false)]
        public static extern int ControlTrace(
            ulong sessionHandle,
            [MarshalAs(UnmanagedType.LPWStr)] string? sessionName,
            EVENT_TRACE_PROPERTIES* properties,
            uint controlCode);

        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport(Advapi32, EntryPoint = "EnableTraceEx2", CharSet = CharSet.Unicode, SetLastError = false)]
        public static extern int EnableTraceEx2(
            ulong sessionHandle,
            Guid* providerId,
            uint controlCode,
            byte level,
            ulong matchAnyKeyword,
            ulong matchAllKeyword,
            uint timeout,
            ENABLE_TRACE_PARAMETERS* enableParameters);

        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport(Advapi32, EntryPoint = "OpenTraceW", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern ulong OpenTrace(EVENT_TRACE_LOGFILE* logfile);

        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport(Advapi32, EntryPoint = "ProcessTrace", SetLastError = false)]
        public static extern int ProcessTrace(
            ulong* handleArray,
            uint handleCount,
            IntPtr startTime,
            IntPtr endTime);

        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport(Advapi32, EntryPoint = "CloseTrace", SetLastError = false)]
        public static extern int CloseTrace(ulong traceHandle);

        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport(Tdh, EntryPoint = "TdhGetEventInformation", SetLastError = false)]
        public static extern int TdhGetEventInformation(
            EVENT_RECORD* eventRecord,
            uint tdhContextCount,
            IntPtr tdhContext,
            TRACE_EVENT_INFO* buffer,
            uint* bufferSize);

        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport(Tdh, EntryPoint = "TdhEnumerateProviders", SetLastError = false)]
        public static extern int TdhEnumerateProviders(
            byte* buffer,
            uint* bufferSize);

        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("ntdll.dll", EntryPoint = "NtQuerySystemInformation", SetLastError = false)]
        public static extern int NtQuerySystemInformation(
            int systemInformationClass,
            void* systemInformation,
            uint systemInformationLength,
            uint* returnLength);

        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("ntdll.dll", EntryPoint = "NtSetSystemInformation", SetLastError = false)]
        public static extern int NtSetSystemInformation(
            int systemInformationClass,
            void* systemInformation,
            uint systemInformationLength);
    }

    /// <summary>
    /// EVENT_TRACE_GROUPMASK_INFORMATION, the undocumented structure the kernel logger uses
    /// to enable providers that have no EVENT_TRACE_FLAG_* bit.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    internal unsafe struct EVENT_TRACE_GROUPMASK_INFORMATION
    {
        public uint EventTraceInformationClass;
        public ulong TraceHandle;
        public fixed uint Masks[8];
    }

    /// <summary>
    /// Header of the buffer returned by TdhEnumerateProviders, followed by
    /// <see cref="NumberOfProviders"/> <see cref="TRACE_PROVIDER_INFO"/> entries.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct PROVIDER_ENUMERATION_INFO
    {
        public uint NumberOfProviders;
        public uint Reserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct TRACE_PROVIDER_INFO
    {
        public Guid ProviderGuid;
        public uint SchemaSource;

        /// <summary>Byte offset of the provider name, relative to the start of the buffer.</summary>
        public uint ProviderNameOffset;
    }
}
