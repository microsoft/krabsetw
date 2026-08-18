using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.O365.Security.ETW.Interop;

namespace Microsoft.O365.Security.ETW
{
    /// <summary>
    /// Reads items out of an event's extended data block.
    /// </summary>
    internal static unsafe class ExtendedData
    {
        /// <summary>
        /// Container id, present when the session was enabled with
        /// EVENT_ENABLE_PROPERTY_SOURCE_CONTAINER_TRACKING.
        /// </summary>
        /// <remarks>
        /// ETW delivers this as a 36-character ANSI GUID string with no braces, not as a
        /// binary GUID.
        /// </remarks>
        public static bool TryGetContainerId(EVENT_RECORD* record, out Guid result)
        {
            result = default;

            if (!TryFind(record, NativeConstants.EVENT_HEADER_EXT_TYPE_CONTAINER_ID, out byte* data, out ushort size))
            {
                return false;
            }

            const int GuidStringLength = 36;
            if (size < GuidStringLength)
            {
                return false;
            }

            char* buffer = stackalloc char[GuidStringLength];
            for (int i = 0; i < GuidStringLength; i++)
            {
                buffer[i] = (char)data[i];
            }

            return Guid.TryParse(new string(buffer, 0, GuidStringLength), out result);
        }

        /// <summary>
        /// Process start key, present when the session was enabled with
        /// EVENT_ENABLE_PROPERTY_PROCESS_START_KEY.
        /// </summary>
        public static bool TryGetProcessStartKey(EVENT_RECORD* record, out ulong result)
        {
            result = 0;

            if (!TryFind(record, NativeConstants.EVENT_HEADER_EXT_TYPE_PROCESS_START_KEY, out byte* data, out ushort size))
            {
                return false;
            }

            if (size < sizeof(ulong))
            {
                return false;
            }

            for (int i = 0; i < sizeof(ulong); i++)
            {
                result |= (ulong)data[i] << (i * 8);
            }

            return true;
        }

        /// <summary>
        /// Return addresses captured with the event, present when the session was enabled
        /// with EVENT_ENABLE_PROPERTY_STACK_TRACE.
        /// </summary>
        /// <remarks>
        /// Both EVENT_EXTENDED_ITEM_STACK_TRACE32 and _TRACE64 begin with a ULONG64
        /// MatchId, so the address array in either case starts eight bytes in. Port of
        /// krabs::schema::stack_trace.
        /// </remarks>
        public static List<ulong> GetStackTrace(EVENT_RECORD* record)
        {
            var result = new List<ulong>();

            if (record == null || record->ExtendedDataCount == 0 || record->ExtendedData == IntPtr.Zero)
            {
                return result;
            }

            var items = (EVENT_HEADER_EXTENDED_DATA_ITEM*)record->ExtendedData;

            for (int i = 0; i < record->ExtendedDataCount; i++)
            {
                ushort extType = items[i].ExtType;
                var data = (byte*)items[i].DataPtr;
                int size = items[i].DataSize;

                if (data == null || size <= sizeof(ulong))
                {
                    continue;
                }

                if (extType == NativeConstants.EVENT_HEADER_EXT_TYPE_STACK_TRACE64)
                {
                    int count = (size - sizeof(ulong)) / sizeof(ulong);
                    for (int j = 0; j < count; j++)
                    {
                        result.Add(Read64(data + sizeof(ulong) + (j * sizeof(ulong))));
                    }
                }
                else if (extType == NativeConstants.EVENT_HEADER_EXT_TYPE_STACK_TRACE32)
                {
                    int count = (size - sizeof(ulong)) / sizeof(uint);
                    for (int j = 0; j < count; j++)
                    {
                        result.Add(Read32(data + sizeof(ulong) + (j * sizeof(uint))));
                    }
                }
            }

            return result;
        }

        private static ulong Read64(byte* p)
        {
            ulong value = 0;
            for (int i = 0; i < 8; i++)
            {
                value |= (ulong)p[i] << (i * 8);
            }

            return value;
        }

        private static ulong Read32(byte* p)
        {
            return (uint)(p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24));
        }

        private static bool TryFind(EVENT_RECORD* record, ushort extType, out byte* data, out ushort size)
        {
            data = null;
            size = 0;

            if (record == null || record->ExtendedDataCount == 0 || record->ExtendedData == IntPtr.Zero)
            {
                return false;
            }

            var items = (EVENT_HEADER_EXTENDED_DATA_ITEM*)record->ExtendedData;

            for (int i = 0; i < record->ExtendedDataCount; i++)
            {
                if (items[i].ExtType != extType)
                {
                    continue;
                }

                data = (byte*)items[i].DataPtr;
                size = items[i].DataSize;
                return data != null && size != 0;
            }

            return false;
        }
    }
}
