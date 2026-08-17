using System;
using System.Runtime.CompilerServices;
using Microsoft.O365.Security.ETW.Interop;

namespace Microsoft.O365.Security.ETW.Schema
{
    /// <summary>
    /// Computes property sizes from schema metadata and, where the schema is not enough,
    /// from the event payload itself.
    /// </summary>
    /// <remarks>
    /// The rules implemented here are the ones documented against each TDH_IN_TYPE in tdh.h.
    /// Two of them differ from what native krabs does, deliberately:
    ///
    /// - For TDH_INTYPE_UNICODESTRING the length is a count of WCHARs, not bytes. Native
    ///   krabs::size_provider returns epi.length unscaled, which halves every fixed-width
    ///   unicode string.
    /// - For TDH_INTYPE_WBEMSID the SE_TOKEN_USER prefix is sized from the *producing*
    ///   process's pointer width, taken from EVENT_HEADER.Flags, not from our own.
    ///
    /// A length of -1 throughout means "the schema did not specify one". That is distinct
    /// from a specified length of 0, which is a legitimately empty field; conflating the two
    /// makes an empty string swallow the rest of the payload.
    /// </remarks>
    internal static unsafe class PropertySizer
    {
        /// <summary>Passed as a length to mean "the schema did not specify one".</summary>
        public const int LengthUnspecified = -1;

        /// <summary>
        /// Returns the size of a property when it can be determined from the schema alone,
        /// or -1 when the size depends on the payload.
        /// </summary>
        public static int TryGetFixedSize(uint flags, ushort inType, ushort outType, ushort length, ushort count, int pointerSize)
        {
            // Structs and payload-derived lengths/counts can't be resolved statically.
            if ((flags & NativeConstants.PropertyStruct) != 0 ||
                (flags & NativeConstants.PropertyParamLength) != 0 ||
                (flags & NativeConstants.PropertyParamCount) != 0 ||
                (flags & NativeConstants.PropertyHasCustomSchema) != 0)
            {
                return -1;
            }

            int elementSize = TryGetFixedElementSize(
                inType,
                outType,
                length == 0 ? LengthUnspecified : length,
                pointerSize);

            if (elementSize < 0)
            {
                return -1;
            }

            int elements = count == 0 ? 1 : count;
            long size = (long)elementSize * elements;

            // EVENT_RECORD.UserDataLength is a ushort, so nothing at or past 64 KiB is ever
            // readable from a payload. Rejecting an oversized product here rather than
            // letting it truncate to int is what stops a pathological schema -- say a 32769
            // char string with a count of 65535 -- from wrapping to a small, in-range offset
            // and silently decoding later properties from the wrong bytes. Returning -1
            // instead sends them down the runtime walk, which bounds every read.
            if (size > ushort.MaxValue)
            {
                return -1;
            }

            return (int)size;
        }

        /// <summary>
        /// Returns the size of a single element when determinable without reading the
        /// payload, else -1.
        /// </summary>
        /// <param name="inType">TDH in-type of the property.</param>
        /// <param name="outType">TDH out-type of the property.</param>
        /// <param name="length">
        /// Element length from the schema, in the unit the in-type documents, or
        /// <see cref="LengthUnspecified"/>.
        /// </param>
        /// <param name="pointerSize">Pointer size of the event source, in bytes.</param>
        public static int TryGetFixedElementSize(ushort inType, ushort outType, int length, int pointerSize)
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
                    // epi.length is a count of WCHARs for this in-type.
                    return length >= 0 ? length * 2 : -1;

                case TdhInType.AnsiString:
                    return length >= 0 ? length : -1;

                case TdhInType.Binary:
                    if (length >= 0)
                    {
                        return length;
                    }

                    // A length-less BINARY is only well formed when it is an IPv6 address.
                    return (TdhOutType)outType == TdhOutType.Ipv6 ? 16 : -1;

                default:
                    // Counted strings, SIDs, hex dumps and anything unrecognised need the
                    // payload.
                    return -1;
            }
        }

        /// <summary>
        /// Computes the size of a property from the payload. <paramref name="data"/> must start
        /// at the property. Returns -1 when the property cannot be decoded.
        /// </summary>
        /// <remarks>
        /// A count of zero is an empty array, which occupies no bytes; a scalar is one element.
        /// Which of those a schema count of zero means depends on whether the count came from
        /// the payload, so the caller resolves it rather than this method guessing.
        /// </remarks>
        public static int GetRuntimeSize(
            ushort inType,
            ushort outType,
            int length,
            int count,
            int pointerSize,
            byte* data,
            int remaining)
        {
            if (count < 0 || remaining < 0)
            {
                return -1;
            }

            int elements = count;
            int total = 0;

            for (int e = 0; e < elements; e++)
            {
                int size = GetSingleRuntimeSize(inType, outType, length, pointerSize, data + total, remaining - total);
                if (size < 0)
                {
                    return -1;
                }

                total += size;
                if (total > remaining)
                {
                    return -1;
                }

                // A zero-width element repeated N times can never make progress, and for a
                // payload-derived count N may be very large. Stop rather than spin.
                if (size == 0)
                {
                    return total;
                }
            }

            return total;
        }

        private static int GetSingleRuntimeSize(ushort inType, ushort outType, int length, int pointerSize, byte* data, int remaining)
        {
            if (remaining < 0)
            {
                return -1;
            }

            switch ((TdhInType)inType)
            {
                case TdhInType.UnicodeString:
                    // Specified in WCHARs. A specified length of zero is an empty field.
                    if (length >= 0)
                    {
                        return length * 2;
                    }

                    return NullTerminatedUtf16Size(data, remaining);

                case TdhInType.AnsiString:
                    if (length >= 0)
                    {
                        return length;
                    }

                    return NullTerminatedAnsiSize(data, remaining);

                case TdhInType.NonNullTerminatedString:
                case TdhInType.NonNullTerminatedAnsiString:
                    // Documented as running to the end of the event.
                    return length >= 0
                        ? ((TdhInType)inType == TdhInType.NonNullTerminatedString ? length * 2 : length)
                        : remaining;

                case TdhInType.CountedString:
                case TdhInType.CountedAnsiString:
                case TdhInType.ManifestCountedString:
                case TdhInType.ManifestCountedAnsiString:
                case TdhInType.ManifestCountedBinary:
                    if (remaining < 2)
                    {
                        return -1;
                    }

                    return Bounded(2 + ReadUInt16LE(data), remaining);

                case TdhInType.ReversedCountedString:
                case TdhInType.ReversedCountedAnsiString:
                    if (remaining < 2)
                    {
                        return -1;
                    }

                    return Bounded(2 + ReadUInt16BE(data), remaining);

                case TdhInType.HexDump:
                    if (remaining < 4)
                    {
                        return -1;
                    }

                    return Bounded(4L + ReadUInt32LE(data), remaining);

                case TdhInType.Sid:
                case TdhInType.WbemSid:
                    return SidSize(inType, pointerSize, data, remaining);

                default:
                    return TryGetFixedElementSize(inType, outType, length, pointerSize);
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static int Bounded(long size, int remaining)
        {
            return size >= 0 && size <= remaining ? (int)size : -1;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static ushort ReadUInt16LE(byte* p)
        {
            return (ushort)(p[0] | (p[1] << 8));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static ushort ReadUInt16BE(byte* p)
        {
            return (ushort)((p[0] << 8) | p[1]);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint ReadUInt32LE(byte* p)
        {
            return (uint)(p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24));
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

            // Unterminated: the string runs to the end of the payload. Providers get this
            // wrong often enough that TDH tolerates it, so we do too.
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
        /// </summary>
        /// <remarks>
        /// A WBEM SID is an SE_TOKEN_USER, which begins with a TOKEN_USER (a pointer plus a
        /// DWORD, pointer aligned) and then a SID_AND_ATTRIBUTES with the same shape. The
        /// pointer width is the *producing* process's, not ours: a 32-bit process logging on
        /// a 64-bit machine emits a 8-byte prefix, and using IntPtr.Size here misreads it.
        /// </remarks>
        private static int SidSize(ushort inType, int pointerSize, byte* data, int remaining)
        {
            int prefix = 0;
            if ((TdhInType)inType == TdhInType.WbemSid)
            {
                prefix = pointerSize == 8 ? 16 : 8;
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
