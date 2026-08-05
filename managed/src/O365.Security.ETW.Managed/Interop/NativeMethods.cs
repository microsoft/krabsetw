using System;
using System.Runtime.InteropServices;

namespace O365.Security.ETW.Interop
{
    /// <summary>
    /// Raw P/Invoke surface. Signatures are deliberately pointer-only and blittable so the
    /// generated marshalling stubs stay trivial - nothing here should require a marshaller.
    /// </summary>
    internal static unsafe class NativeMethods
    {
        private const string Advapi32 = "advapi32.dll";
        private const string Tdh = "tdh.dll";

        [DllImport(Advapi32, EntryPoint = "StartTraceW", CharSet = CharSet.Unicode, SetLastError = false)]
        public static extern int StartTrace(
            out ulong sessionHandle,
            [MarshalAs(UnmanagedType.LPWStr)] string sessionName,
            EVENT_TRACE_PROPERTIES* properties);

        [DllImport(Advapi32, EntryPoint = "ControlTraceW", CharSet = CharSet.Unicode, SetLastError = false)]
        public static extern int ControlTrace(
            ulong sessionHandle,
            [MarshalAs(UnmanagedType.LPWStr)] string sessionName,
            EVENT_TRACE_PROPERTIES* properties,
            uint controlCode);

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

        [DllImport(Advapi32, EntryPoint = "OpenTraceW", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern ulong OpenTrace(EVENT_TRACE_LOGFILE* logfile);

        [DllImport(Advapi32, EntryPoint = "ProcessTrace", SetLastError = false)]
        public static extern int ProcessTrace(
            ulong* handleArray,
            uint handleCount,
            IntPtr startTime,
            IntPtr endTime);

        [DllImport(Advapi32, EntryPoint = "CloseTrace", SetLastError = false)]
        public static extern int CloseTrace(ulong traceHandle);

        [DllImport(Tdh, EntryPoint = "TdhGetEventInformation", SetLastError = false)]
        public static extern int TdhGetEventInformation(
            EVENT_RECORD* eventRecord,
            uint tdhContextCount,
            IntPtr tdhContext,
            TRACE_EVENT_INFO* buffer,
            uint* bufferSize);
    }
}
