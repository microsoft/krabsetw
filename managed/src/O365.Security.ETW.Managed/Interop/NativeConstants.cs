using System;

namespace Microsoft.O365.Security.ETW.Interop
{
    internal static class NativeConstants
    {
        // Win32 error codes
        public const int ERROR_SUCCESS = 0;
        public const int ERROR_INVALID_PARAMETER = 87;
        public const int ERROR_BAD_LENGTH = 24;
        public const int ERROR_INSUFFICIENT_BUFFER = 122;
        public const int ERROR_ALREADY_EXISTS = 183;
        public const int ERROR_NOT_FOUND = 1168;
        public const int ERROR_WMI_INSTANCE_NOT_FOUND = 4201;
        public const int ERROR_CTX_CLOSE_PENDING = 7007;
        public const int ERROR_NO_SYSTEM_RESOURCES = 1450;
        public const int ERROR_ACCESS_DENIED = 5;
        public const int ERROR_CANCELLED = 1223;
        public const int ERROR_MORE_DATA = 234;
        public const int ERROR_NOT_SUPPORTED = 50;

        // WNODE flags
        public const uint WNODE_FLAG_TRACED_GUID = 0x00020000;

        // Log file modes
        public const uint EVENT_TRACE_REAL_TIME_MODE = 0x00000100;

        /// <summary>Marks the session as a system (NT kernel) logger. Windows 8 and later.</summary>
        public const uint EVENT_TRACE_SYSTEM_LOGGER_MODE = 0x02000000;

        /// <summary>SYSTEM_INFORMATION_CLASS::SystemPerformanceTraceInformation.</summary>
        public const int SystemPerformanceTraceInformation = 31;

        /// <summary>EVENT_TRACE_INFORMATION_CLASS::EventTraceGroupMaskInformation.</summary>
        public const uint EventTraceGroupMaskInformation = 3;
        public const uint EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING = 0x10000000;

        // Process trace modes
        public const uint PROCESS_TRACE_MODE_REAL_TIME = 0x00000100;
        public const uint PROCESS_TRACE_MODE_EVENT_RECORD = 0x10000000;
        public const uint PROCESS_TRACE_MODE_RAW_TIMESTAMP = 0x00001000;

        // Trace control codes
        public const uint EVENT_TRACE_CONTROL_QUERY = 0;
        public const uint EVENT_TRACE_CONTROL_STOP = 1;
        public const uint EVENT_TRACE_CONTROL_UPDATE = 2;
        public const uint EVENT_TRACE_CONTROL_FLUSH = 3;

        // EnableTraceEx2 control codes
        public const uint EVENT_CONTROL_CODE_DISABLE_PROVIDER = 0;
        public const uint EVENT_CONTROL_CODE_ENABLE_PROVIDER = 1;
        public const uint EVENT_CONTROL_CODE_CAPTURE_STATE = 2;

        public const uint ENABLE_TRACE_PARAMETERS_VERSION_2 = 2;

        // Filter types
        public const uint EVENT_FILTER_TYPE_EVENT_ID = 0x80000200;

        // Extended data item types
        public const ushort EVENT_HEADER_EXT_TYPE_RELATED_ACTIVITYID = 0x0001;
        public const ushort EVENT_HEADER_EXT_TYPE_SID = 0x0002;
        public const ushort EVENT_HEADER_EXT_TYPE_TS_ID = 0x0003;
        public const ushort EVENT_HEADER_EXT_TYPE_INSTANCE_INFO = 0x0004;
        public const ushort EVENT_HEADER_EXT_TYPE_STACK_TRACE32 = 0x0005;
        public const ushort EVENT_HEADER_EXT_TYPE_STACK_TRACE64 = 0x0006;
        public const ushort EVENT_HEADER_EXT_TYPE_EVENT_KEY = 0x000A;
        public const ushort EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL = 0x000B;
        public const ushort EVENT_HEADER_EXT_TYPE_PROV_TRAITS = 0x000C;
        public const ushort EVENT_HEADER_EXT_TYPE_PROCESS_START_KEY = 0x000D;
        public const ushort EVENT_HEADER_EXT_TYPE_CONTROL_GUID = 0x000E;
        public const ushort EVENT_HEADER_EXT_TYPE_QPC_DELTA = 0x000F;
        public const ushort EVENT_HEADER_EXT_TYPE_CONTAINER_ID = 0x0010;
        public const ushort EVENT_HEADER_EXT_TYPE_STACK_KEY32 = 0x0011;
        public const ushort EVENT_HEADER_EXT_TYPE_STACK_KEY64 = 0x0012;

        public const int MAX_EVENT_FILTER_EVENT_ID_COUNT = 64;

        public const uint EVENT_ENABLE_PROPERTY_SID = 0x00000001;
        public const uint EVENT_ENABLE_PROPERTY_TS_ID = 0x00000002;
        public const uint EVENT_ENABLE_PROPERTY_STACK_TRACE = 0x00000004;
        public const uint EVENT_ENABLE_PROPERTY_PROCESS_START_KEY = 0x00000080;
        public const uint EVENT_ENABLE_PROPERTY_EVENT_KEY = 0x00000100;
        public const uint EVENT_ENABLE_PROPERTY_SOURCE_CONTAINER_TRACKING = 0x00000800;

        // EVENT_HEADER flags
        public const ushort EVENT_HEADER_FLAG_EXTENDED_INFO = 0x0001;
        public const ushort EVENT_HEADER_FLAG_PRIVATE_SESSION = 0x0002;
        public const ushort EVENT_HEADER_FLAG_STRING_ONLY = 0x0004;
        public const ushort EVENT_HEADER_FLAG_TRACE_MESSAGE = 0x0008;
        public const ushort EVENT_HEADER_FLAG_NO_CPUTIME = 0x0010;
        public const ushort EVENT_HEADER_FLAG_32_BIT_HEADER = 0x0020;
        public const ushort EVENT_HEADER_FLAG_64_BIT_HEADER = 0x0040;
        public const ushort EVENT_HEADER_FLAG_CLASSIC_HEADER = 0x0100;
        public const ushort EVENT_HEADER_FLAG_PROCESSOR_INDEX = 0x0200;

        // PROPERTY_FLAGS
        public const uint PropertyStruct = 0x1;
        public const uint PropertyParamLength = 0x2;
        public const uint PropertyParamCount = 0x4;
        public const uint PropertyWBEMXmlFragment = 0x8;
        public const uint PropertyParamFixedLength = 0x10;
        public const uint PropertyParamFixedCount = 0x20;
        public const uint PropertyHasTags = 0x40;
        public const uint PropertyHasCustomSchema = 0x80;

        // Invalid handle value for trace handles (64-bit sessions use ulong.MaxValue).
        public static readonly ulong INVALID_PROCESSTRACE_HANDLE =
            IntPtr.Size == 8 ? ulong.MaxValue : 0x00000000FFFFFFFFUL;
    }

    /// <summary>TDH_IN_TYPE values.</summary>
    internal enum TdhInType : ushort
    {
        Null = 0,
        UnicodeString = 1,
        AnsiString = 2,
        Int8 = 3,
        UInt8 = 4,
        Int16 = 5,
        UInt16 = 6,
        Int32 = 7,
        UInt32 = 8,
        Int64 = 9,
        UInt64 = 10,
        Float = 11,
        Double = 12,
        Boolean = 13,
        Binary = 14,
        Guid = 15,
        Pointer = 16,
        FileTime = 17,
        SystemTime = 18,
        Sid = 19,
        HexInt32 = 20,
        HexInt64 = 21,
        ManifestCountedString = 22,
        ManifestCountedAnsiString = 23,
        ManifestCountedBinary = 25,
        CountedString = 300,
        CountedAnsiString = 301,
        ReversedCountedString = 302,
        ReversedCountedAnsiString = 303,
        NonNullTerminatedString = 304,
        NonNullTerminatedAnsiString = 305,
        UnicodeChar = 306,
        AnsiChar = 307,
        SizeT = 308,
        HexDump = 309,
        WbemSid = 310
    }

    /// <summary>TDH_OUT_TYPE values (subset that affects decoding).</summary>
    internal enum TdhOutType : ushort
    {
        Null = 0,
        String = 1,
        DateTime = 2,
        Byte = 3,
        UnsignedByte = 4,
        Short = 5,
        UnsignedShort = 6,
        Int = 7,
        UnsignedInt = 8,
        Long = 9,
        UnsignedLong = 10,
        Float = 11,
        Double = 12,
        Boolean = 13,
        Guid = 14,
        HexBinary = 15,
        HexInt8 = 16,
        HexInt16 = 17,
        HexInt32 = 18,
        HexInt64 = 19,
        Pid = 20,
        Tid = 21,
        Port = 22,
        Ipv4 = 23,
        Ipv6 = 24,
        SocketAddress = 25,
        Etwtime = 30,
        Xml = 31,
        ErrorCode = 32,
        Win32Error = 33,
        Ntstatus = 34,
        Hresult = 35,
        CultureInsensitiveDatetime = 36,
        Json = 37,
        Utf8 = 38,
        Pkcs7WithTypeInfo = 39,
        CodePointer = 40,
        DatetimeUtc = 41
    }
}
