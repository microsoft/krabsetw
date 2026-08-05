using System;
using System.Runtime.CompilerServices;
using O365.Security.ETW.Interop;

namespace O365.Security.ETW.Schema
{
    /// <summary>
    /// Computes property sizes from schema metadata and, where the schema is not enough,
    /// from the event payload itself.
    /// </summary>
    internal static unsafe class PropertySizer
    {
        /// <summary>
        /// Returns the size of a property when it can be determined from the schema alone,
        /// or -1 when the size depends on the payload.
        /// </summary>
        public static int TryGetFixedSize(uint flags, ushort inType, ushort length, ushort count, int pointerSize)
        {
            // Structs and payload-derived lengths/counts can't be resolved statically.
            if ((flags & NativeConstants.PropertyStruct) != 0 ||
                (flags & NativeConstants.PropertyParamLength) != 0 ||
                (flags & NativeConstants.PropertyParamCount) != 0 ||
                (flags & NativeConstants.PropertyHasCustomSchema) != 0)
            {
                return -1;
            }

            int elementSize = TryGetFixedElementSize(inType, length, pointerSize);
            if (elementSize < 0)
            {
                return -1;
            }

            int elements = count == 0 ? 1 : count;
            return elementSize * elements;
        }

        /// <summary>
        /// Returns the size of a single element when determinable from the schema, else -1.
        /// </summary>
        public static int TryGetFixedElementSize(ushort inType, ushort length, int pointerSize)
        {
            switch ((TdhInType)inType)
            {
                case TdhInType.Int8:
                case TdhInType.UInt8:
                case TdhInType.AnsiChar:
                    return 1;

                case TdhInType.Int16:
                case TdhInType.UInt16:
                case TdhInType.UnicodeChar:
                    return 2;

                case TdhInType.Int32:
                case TdhInType.UInt32:
                case TdhInType.HexInt32:
                case TdhInType.Float:
                case TdhInType.Boolean:
                    return 4;

                case TdhInType.Int64:
                case TdhInType.UInt64:
                case TdhInType.HexInt64:
                case TdhInType.Double:
                case TdhInType.FileTime:
                    return 8;

                case TdhInType.Guid:
                case TdhInType.SystemTime:
                    return 16;

                case TdhInType.Pointer:
                case TdhInType.SizeT:
                    return pointerSize;

                case TdhInType.UnicodeString:
                case TdhInType.NonNullTerminatedString:
                    // A non-zero length in the schema means a fixed-width character field.
                    return length > 0 ? length * 2 : -1;

                case TdhInType.AnsiString:
                case TdhInType.NonNullTerminatedAnsiString:
                    return length > 0 ? length : -1;

                case TdhInType.Binary:
                case TdhInType.HexDump:
                    return length > 0 ? length : -1;

                default:
                    // Counted strings, SIDs and anything unrecognised need the payload.
                    return -1;
            }
        }

        /// <summary>
        /// Computes the size of a property from the payload. <paramref name="data"/> must start
        /// at the property. Returns -1 when the property cannot be decoded.
        /// </summary>
        public static int GetRuntimeSize(
            ushort inType,
            ushort length,
            int count,
            int pointerSize,
            byte* data,
            int remaining)
        {
            int elements = count == 0 ? 1 : count;
            int total = 0;

            for (int e = 0; e < elements; e++)
            {
                int size = GetSingleRuntimeSize(inType, length, pointerSize, data + total, remaining - total);
                if (size < 0)
                {
                    return -1;
                }

                total += size;
                if (total > remaining)
                {
                    return -1;
                }
            }

            return total;
        }

        private static int GetSingleRuntimeSize(ushort inType, ushort length, int pointerSize, byte* data, int remaining)
        {
            if (remaining < 0)
            {
                return -1;
            }

            switch ((TdhInType)inType)
            {
                case TdhInType.UnicodeString:
                    if (length > 0)
                    {
                        return length * 2;
                    }

                    return NullTerminatedUtf16Size(data, remaining);

                case TdhInType.AnsiString:
                    if (length > 0)
                    {
                        return length;
                    }

                    return NullTerminatedAnsiSize(data, remaining);

                case TdhInType.CountedString:
                case TdhInType.NonNullTerminatedString when length == 0:
                    if (remaining < 2)
                    {
                        return -1;
                    }

                    return 2 + ReadUInt16(data);

                case TdhInType.CountedAnsiString:
                    if (remaining < 2)
                    {
                        return -1;
                    }

                    return 2 + ReadUInt16(data);

                case TdhInType.Sid:
                case TdhInType.WbemSid:
                    return SidSize(inType, data, remaining);

                default:
                    int fixedSize = TryGetFixedElementSize(inType, length, pointerSize);
                    return fixedSize;
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static ushort ReadUInt16(byte* p)
        {
            return (ushort)(p[0] | (p[1] << 8));
        }

        private static int NullTerminatedUtf16Size(byte* data, int remaining)
        {
            int i = 0;
            while (i + 1 < remaining)
            {
                if (data[i] == 0 && data[i + 1] == 0)
                {
                    return i + 2;
                }

                i += 2;
            }

            // Unterminated: the string runs to the end of the payload.
            return remaining;
        }

        private static int NullTerminatedAnsiSize(byte* data, int remaining)
        {
            int i = 0;
            while (i < remaining)
            {
                if (data[i] == 0)
                {
                    return i + 1;
                }

                i++;
            }

            return remaining;
        }

        /// <summary>
        /// SID layout: Revision(1) SubAuthorityCount(1) IdentifierAuthority(6) SubAuthority[n](4n).
        /// A WBEM SID is preceded by two pointer-sized values (TOKEN_USER).
        /// </summary>
        private static int SidSize(ushort inType, byte* data, int remaining)
        {
            int prefix = 0;
            if ((TdhInType)inType == TdhInType.WbemSid)
            {
                // TOKEN_USER contains a SID_AND_ATTRIBUTES: a pointer plus a DWORD, padded.
                prefix = IntPtr.Size == 8 ? 16 : 8;
            }

            if (remaining < prefix + 8)
            {
                return -1;
            }

            byte subAuthorityCount = data[prefix + 1];
            int size = prefix + 8 + (subAuthorityCount * 4);

            return size <= remaining ? size : -1;
        }
    }
}
