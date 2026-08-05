using System;
using System.Text;
using O365.Security.ETW.Interop;

namespace O365.Security.ETW
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
