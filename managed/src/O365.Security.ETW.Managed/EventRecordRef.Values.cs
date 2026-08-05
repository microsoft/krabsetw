using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using O365.Security.ETW.Interop;

namespace O365.Security.ETW
{
    /// <summary>
    /// Typed property accessors.
    /// </summary>
    /// <remarks>
    /// The span-returning members are the zero-allocation path: they hand back a view into
    /// the event payload. The string-returning members exist for API compatibility and
    /// allocate exactly one string, which is unavoidable given their return type.
    /// </remarks>
    public readonly unsafe ref partial struct EventRecordRef
    {
        #region Strings

        /// <summary>
        /// Returns a UTF-16 string property as a view into the payload. No allocation, no copy.
        /// </summary>
        public bool TryGetUnicodeString(ReadOnlySpan<char> name, out ReadOnlySpan<char> value)
        {
            value = default;

            int index = IndexOf(name);
            if (index < 0 || !TryGetRaw(index, out ReadOnlySpan<byte> raw))
            {
                return false;
            }

            value = DecodeUnicode(raw, InTypeAt(index));
            return true;
        }

        public ReadOnlySpan<char> GetUnicodeString(ReadOnlySpan<char> name)
        {
            if (!TryGetUnicodeString(name, out ReadOnlySpan<char> value))
            {
                ThrowMissing(name);
            }

            return value;
        }

        /// <summary>
        /// Returns an ANSI string property as raw bytes, without transcoding. Callers that
        /// only need to compare should use this and compare bytes.
        /// </summary>
        public bool TryGetAnsiStringBytes(ReadOnlySpan<char> name, out ReadOnlySpan<byte> value)
        {
            value = default;

            int index = IndexOf(name);
            if (index < 0 || !TryGetRaw(index, out ReadOnlySpan<byte> raw))
            {
                return false;
            }

            value = DecodeAnsi(raw, InTypeAt(index));
            return true;
        }

        private static ReadOnlySpan<char> DecodeUnicode(ReadOnlySpan<byte> raw, ushort inType)
        {
            switch ((TdhInType)inType)
            {
                case TdhInType.CountedString:
                case TdhInType.ReversedCountedString:
                    if (raw.Length < 2)
                    {
                        return default;
                    }

                    // Leading UINT16 is a byte count.
                    return Reinterpret(raw.Slice(2));

                default:
                    return TrimTerminator(Reinterpret(raw));
            }
        }

        private static ReadOnlySpan<byte> DecodeAnsi(ReadOnlySpan<byte> raw, ushort inType)
        {
            switch ((TdhInType)inType)
            {
                case TdhInType.CountedAnsiString:
                case TdhInType.ReversedCountedAnsiString:
                    return raw.Length < 2 ? default : raw.Slice(2);

                default:
                    int length = raw.Length;
                    while (length > 0 && raw[length - 1] == 0)
                    {
                        length--;
                    }

                    return raw.Slice(0, length);
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static ReadOnlySpan<char> Reinterpret(ReadOnlySpan<byte> raw)
        {
            // ETW payloads carry no alignment guarantee, so this may be an unaligned view.
            // Unaligned 16-bit reads are supported on every architecture we target.
            return MemoryMarshal.Cast<byte, char>(raw);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static ReadOnlySpan<char> TrimTerminator(ReadOnlySpan<char> value)
        {
            int length = value.Length;
            while (length > 0 && value[length - 1] == '\0')
            {
                length--;
            }

            return value.Slice(0, length);
        }

        #endregion

        #region Integers

        public bool TryGetUInt8(ReadOnlySpan<char> name, out byte value)
        {
            value = 0;
            if (!TryGetFixed(name, 1, out byte* p))
            {
                return false;
            }

            value = *p;
            return true;
        }

        public bool TryGetInt8(ReadOnlySpan<char> name, out sbyte value)
        {
            value = 0;
            if (!TryGetFixed(name, 1, out byte* p))
            {
                return false;
            }

            value = (sbyte)*p;
            return true;
        }

        public bool TryGetUInt16(ReadOnlySpan<char> name, out ushort value)
        {
            value = 0;
            if (!TryGetFixed(name, 2, out byte* p))
            {
                return false;
            }

            value = Unsafe.ReadUnaligned<ushort>(p);
            return true;
        }

        public bool TryGetInt16(ReadOnlySpan<char> name, out short value)
        {
            value = 0;
            if (!TryGetFixed(name, 2, out byte* p))
            {
                return false;
            }

            value = Unsafe.ReadUnaligned<short>(p);
            return true;
        }

        public bool TryGetUInt32(ReadOnlySpan<char> name, out uint value)
        {
            value = 0;
            if (!TryGetFixed(name, 4, out byte* p))
            {
                return false;
            }

            value = Unsafe.ReadUnaligned<uint>(p);
            return true;
        }

        public bool TryGetInt32(ReadOnlySpan<char> name, out int value)
        {
            value = 0;
            if (!TryGetFixed(name, 4, out byte* p))
            {
                return false;
            }

            value = Unsafe.ReadUnaligned<int>(p);
            return true;
        }

        public bool TryGetUInt64(ReadOnlySpan<char> name, out ulong value)
        {
            value = 0;
            if (!TryGetFixed(name, 8, out byte* p))
            {
                return false;
            }

            value = Unsafe.ReadUnaligned<ulong>(p);
            return true;
        }

        public bool TryGetInt64(ReadOnlySpan<char> name, out long value)
        {
            value = 0;
            if (!TryGetFixed(name, 8, out byte* p))
            {
                return false;
            }

            value = Unsafe.ReadUnaligned<long>(p);
            return true;
        }

        public bool TryGetGuid(ReadOnlySpan<char> name, out Guid value)
        {
            value = default;
            if (!TryGetFixed(name, 16, out byte* p))
            {
                return false;
            }

            value = Unsafe.ReadUnaligned<Guid>(p);
            return true;
        }

        public bool TryGetBoolean(ReadOnlySpan<char> name, out bool value)
        {
            value = false;
            if (!TryGetUInt32(name, out uint raw))
            {
                return false;
            }

            value = raw != 0;
            return true;
        }

        public bool TryGetPointer(ReadOnlySpan<char> name, out ulong value)
        {
            value = 0;

            int index = IndexOf(name);
            if (index < 0 || !TryGetRaw(index, out ReadOnlySpan<byte> raw))
            {
                return false;
            }

            fixed (byte* p = raw)
            {
                if (raw.Length == 8)
                {
                    value = Unsafe.ReadUnaligned<ulong>(p);
                    return true;
                }

                if (raw.Length == 4)
                {
                    value = Unsafe.ReadUnaligned<uint>(p);
                    return true;
                }
            }

            return false;
        }

        public bool TryGetBinary(ReadOnlySpan<char> name, out ReadOnlySpan<byte> value)
        {
            return TryGetRaw(name, out value);
        }

        private bool TryGetFixed(ReadOnlySpan<char> name, int size, out byte* pointer)
        {
            pointer = null;

            int index = IndexOf(name);
            if (index < 0 || !TryGetRaw(index, out ReadOnlySpan<byte> raw))
            {
                return false;
            }

            if (raw.Length < size)
            {
                return false;
            }

            pointer = (byte*)Unsafe.AsPointer(ref MemoryMarshal.GetReference(raw));
            return true;
        }

        #endregion

        private static void ThrowMissing(ReadOnlySpan<char> name)
        {
            throw new PropertyNotFoundException(name.ToString());
        }
    }

    /// <summary>
    /// Thrown when a requested property is absent from the event schema, or cannot be decoded.
    /// </summary>
    public class PropertyNotFoundException : Exception
    {
        public PropertyNotFoundException(string propertyName)
            : base("Could not find property in event schema: " + propertyName)
        {
            PropertyName = propertyName;
        }

        public string PropertyName { get; }
    }
}
