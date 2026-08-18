using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Microsoft.O365.Security.ETW.Interop;

namespace Microsoft.O365.Security.ETW
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

            if (!TryGetRaw(name, out ReadOnlySpan<byte> raw, out ushort inType))
            {
                return false;
            }

            value = DecodeUnicode(raw, inType);
            return true;
        }

        /// <summary>
        /// As <see cref="TryGetUnicodeString"/>, substituting <paramref name="defaultValue"/>
        /// when the property is absent.
        /// </summary>
        public ReadOnlySpan<char> GetUnicodeString(ReadOnlySpan<char> name, ReadOnlySpan<char> defaultValue)
        {
            return TryGetUnicodeString(name, out ReadOnlySpan<char> value) ? value : defaultValue;
        }

        /// <summary>
        /// Returns an ANSI string property as raw bytes, without transcoding. Callers that
        /// only need to compare should use this and compare bytes.
        /// </summary>
        public bool TryGetAnsiStringBytes(ReadOnlySpan<char> name, out ReadOnlySpan<byte> value)
        {
            return TryGetAnsiStringBytes(name, out value, out _);
        }

        /// <summary>
        /// As <see cref="TryGetAnsiStringBytes(ReadOnlySpan{char}, out ReadOnlySpan{byte})"/>,
        /// also reporting the property's out-type, which decides how the bytes are encoded.
        /// </summary>
        internal bool TryGetAnsiStringBytes(ReadOnlySpan<char> name, out ReadOnlySpan<byte> value, out ushort outType)
        {
            value = default;
            outType = 0;

            if (!TryGetRaw(name, out ReadOnlySpan<byte> raw, out ushort inType, out outType))
            {
                return false;
            }

            value = DecodeAnsi(raw, inType);
            return true;
        }

        /// <summary>
        /// As <see cref="TryGetAnsiStringBytes(ReadOnlySpan{char}, out ReadOnlySpan{byte})"/>,
        /// substituting <paramref name="defaultValue"/> when the property is absent.
        /// </summary>
        public ReadOnlySpan<byte> GetAnsiStringBytes(ReadOnlySpan<char> name, ReadOnlySpan<byte> defaultValue)
        {
            return TryGetAnsiStringBytes(name, out ReadOnlySpan<byte> value) ? value : defaultValue;
        }

        /// <summary>
        /// Reads a property as a counted UTF-16 string: a little-endian UINT16 byte count
        /// followed by that many bytes of character data.
        /// </summary>
        /// <remarks>
        /// Unlike <see cref="TryGetUnicodeString"/> the interpretation is forced rather than
        /// derived from the TDH in-type, matching krabs::predicates::adapters::counted_string.
        /// Classic WBEM schemas routinely describe a length-prefixed field as a plain
        /// UNICODESTRING, and letting the in-type decide would leave the count bytes at the
        /// head of the value.
        /// </remarks>
        public bool TryGetCountedString(ReadOnlySpan<char> name, out ReadOnlySpan<char> value)
        {
            value = default;

            if (!TryGetRaw(name, out ReadOnlySpan<byte> raw) || raw.Length < 2)
            {
                return false;
            }

            int byteCount = raw[0] | (raw[1] << 8);
            ReadOnlySpan<byte> body = raw.Slice(2);

            if (byteCount < body.Length)
            {
                body = body.Slice(0, byteCount);
            }

            // An odd byte count cannot describe whole characters; drop the trailing byte
            // rather than reading past the field.
            value = Reinterpret(body.Slice(0, body.Length & ~1));
            return true;
        }

        /// <summary>
        /// As <see cref="TryGetCountedString"/>, substituting <paramref name="defaultValue"/>
        /// when the property is absent.
        /// </summary>
        public ReadOnlySpan<char> GetCountedString(ReadOnlySpan<char> name, ReadOnlySpan<char> defaultValue)
        {
            return TryGetCountedString(name, out ReadOnlySpan<char> value) ? value : defaultValue;
        }

        private static ReadOnlySpan<char> DecodeUnicode(ReadOnlySpan<byte> raw, ushort inType)
        {
            switch ((TdhInType)inType)
            {
                case TdhInType.CountedString:
                case TdhInType.ReversedCountedString:
                case TdhInType.ManifestCountedString:
                    if (raw.Length < 2)
                    {
                        return default;
                    }

                    // Leading UINT16 is a byte count; the sizer has already bounded the span
                    // to exactly that many bytes plus the prefix.
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
                case TdhInType.ManifestCountedAnsiString:
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
            AssertInType(name, TdhInType.UInt8);
            value = 0;
            if (!TryGetFixed(name, 1, out byte* p))
            {
                return false;
            }

            value = *p;
            return true;
        }

        public byte GetUInt8(ReadOnlySpan<char> name, byte defaultValue)
        {
            return TryGetUInt8(name, out byte value) ? value : defaultValue;
        }

        public bool TryGetInt8(ReadOnlySpan<char> name, out sbyte value)
        {
            AssertInType(name, TdhInType.Int8);
            value = 0;
            if (!TryGetFixed(name, 1, out byte* p))
            {
                return false;
            }

            value = (sbyte)*p;
            return true;
        }

        public sbyte GetInt8(ReadOnlySpan<char> name, sbyte defaultValue)
        {
            return TryGetInt8(name, out sbyte value) ? value : defaultValue;
        }

        public bool TryGetUInt16(ReadOnlySpan<char> name, out ushort value)
        {
            AssertInType(name, TdhInType.UInt16);
            value = 0;
            if (!TryGetFixed(name, 2, out byte* p))
            {
                return false;
            }

            value = Unsafe.ReadUnaligned<ushort>(p);
            return true;
        }

        public ushort GetUInt16(ReadOnlySpan<char> name, ushort defaultValue)
        {
            return TryGetUInt16(name, out ushort value) ? value : defaultValue;
        }

        public bool TryGetInt16(ReadOnlySpan<char> name, out short value)
        {
            AssertInType(name, TdhInType.Int16);
            value = 0;
            if (!TryGetFixed(name, 2, out byte* p))
            {
                return false;
            }

            value = Unsafe.ReadUnaligned<short>(p);
            return true;
        }

        public short GetInt16(ReadOnlySpan<char> name, short defaultValue)
        {
            return TryGetInt16(name, out short value) ? value : defaultValue;
        }

        public bool TryGetUInt32(ReadOnlySpan<char> name, out uint value)
        {
            AssertInType(name, TdhInType.UInt32);
            value = 0;
            if (!TryGetFixed(name, 4, out byte* p))
            {
                return false;
            }

            value = Unsafe.ReadUnaligned<uint>(p);
            return true;
        }

        public uint GetUInt32(ReadOnlySpan<char> name, uint defaultValue)
        {
            return TryGetUInt32(name, out uint value) ? value : defaultValue;
        }

        public bool TryGetInt32(ReadOnlySpan<char> name, out int value)
        {
            AssertInType(name, TdhInType.Int32);
            value = 0;
            if (!TryGetFixed(name, 4, out byte* p))
            {
                return false;
            }

            value = Unsafe.ReadUnaligned<int>(p);
            return true;
        }

        public int GetInt32(ReadOnlySpan<char> name, int defaultValue)
        {
            return TryGetInt32(name, out int value) ? value : defaultValue;
        }

        public bool TryGetUInt64(ReadOnlySpan<char> name, out ulong value)
        {
            AssertInType(name, TdhInType.UInt64);
            value = 0;
            if (!TryGetFixed(name, 8, out byte* p))
            {
                return false;
            }

            value = Unsafe.ReadUnaligned<ulong>(p);
            return true;
        }

        public ulong GetUInt64(ReadOnlySpan<char> name, ulong defaultValue)
        {
            return TryGetUInt64(name, out ulong value) ? value : defaultValue;
        }

        public bool TryGetInt64(ReadOnlySpan<char> name, out long value)
        {
            AssertInType(name, TdhInType.Int64);
            value = 0;
            if (!TryGetFixed(name, 8, out byte* p))
            {
                return false;
            }

            value = Unsafe.ReadUnaligned<long>(p);
            return true;
        }

        public long GetInt64(ReadOnlySpan<char> name, long defaultValue)
        {
            return TryGetInt64(name, out long value) ? value : defaultValue;
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

        public Guid GetGuid(ReadOnlySpan<char> name, Guid defaultValue)
        {
            return TryGetGuid(name, out Guid value) ? value : defaultValue;
        }

        public bool TryGetBoolean(ReadOnlySpan<char> name, out bool value)
        {
            // Deliberately not type-asserted: krabs excludes bool because ETW's
            // representation (a 4-byte BOOL) does not line up with the C++ or C# type.
            value = false;
            if (!TryGetFixed(name, 4, out byte* p))
            {
                return false;
            }

            value = Unsafe.ReadUnaligned<uint>(p) != 0;
            return true;
        }

        public bool GetBoolean(ReadOnlySpan<char> name, bool defaultValue)
        {
            return TryGetBoolean(name, out bool value) ? value : defaultValue;
        }

        public bool TryGetPointer(ReadOnlySpan<char> name, out ulong value)
        {
            value = 0;

            if (!TryGetRaw(name, out ReadOnlySpan<byte> raw))
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

        public ulong GetPointer(ReadOnlySpan<char> name, ulong defaultValue)
        {
            return TryGetPointer(name, out ulong value) ? value : defaultValue;
        }

        public bool TryGetBinary(ReadOnlySpan<char> name, out ReadOnlySpan<byte> value)
        {
            return TryGetRaw(name, out value);
        }

        public ReadOnlySpan<byte> GetBinary(ReadOnlySpan<char> name, ReadOnlySpan<byte> defaultValue)
        {
            return TryGetBinary(name, out ReadOnlySpan<byte> value) ? value : defaultValue;
        }

        private bool TryGetFixed(ReadOnlySpan<char> name, int size, out byte* pointer)
        {
            pointer = null;

            // Resolved once and reused. Going through IndexOf and then TryGetRaw would fetch
            // the schema twice for a single read, and each fetch is a getter pair plus the
            // resolved-yet check. The fixed-width accessors are the ones that notice: their
            // own bodies are a handful of instructions, so the overhead is most of the cost.
            var schema = Schema;
            var table = schema?.Table;
            if (table == null)
            {
                return false;
            }

            int index = table.IndexOf(name, (byte*)schema!.Blob);
            if (index < 0)
            {
                return false;
            }

            var offsets = Offsets;

            int offset = offsets.GetOffset(index);
            if (offset < 0)
            {
                return false;
            }

            // krabs::parser::parse requires sizeof(T) == propInfo.length_ exactly. Accepting
            // a wider property would silently truncate, and the C++/CLI surface reports that
            // as a failed parse rather than a value.
            int actual = offsets.SizeOf(index, offset);
            if (actual != size || offset + actual > _record->UserDataLength)
            {
                return false;
            }

            pointer = (byte*)_record->UserData + offset;
            return true;
        }

        /// <summary>
        /// Fails a read whose requested type does not match the schema's TDH in-type.
        /// </summary>
        /// <remarks>
        /// Debug only, exactly like krabs::debug::assert_valid_assignment. Enforcing it in
        /// release would change the behaviour of shipped consumers that today read, say, an
        /// INT32-typed property through GetUInt32 and get a working value.
        ///
        /// Applied to the fixed-width numeric accessors only. krabs also asserts on strings
        /// because parse&lt;std::wstring&gt; blindly reinterprets the payload; the decoders
        /// here branch on the in-type instead and correctly handle the counted and
        /// non-null-terminated variants, which .NET Framework's TraceLogging emits.
        /// </remarks>
        [Conditional("DEBUG")]
        private void AssertInType(ReadOnlySpan<char> name, TdhInType expected)
        {
            int index = IndexOf(name);

            if (index < 0)
            {
                return;
            }

            var actual = (TdhInType)InTypeAt(index);

            if (actual != expected)
            {
                ThrowTypeMismatch(name, actual, expected);
            }
        }

        private static void ThrowTypeMismatch(ReadOnlySpan<char> name, TdhInType actual, TdhInType expected)
        {
            throw new TypeMismatchAssert(
                "Type mismatch assert for property " + name.ToString()
                + " Actual: " + actual + " Requested: " + expected);
        }

        #endregion

    }
}
