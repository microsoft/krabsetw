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

            int index = IndexOf(name);
            if (index < 0 || !TryGetRaw(index, out ReadOnlySpan<byte> raw))
            {
                return false;
            }

            value = DecodeAnsi(raw, InTypeAt(index));
            outType = OutTypeAt(index);
            return true;
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

            int index = IndexOf(name);
            if (index < 0 || !TryGetRaw(index, out ReadOnlySpan<byte> raw) || raw.Length < 2)
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

        public ReadOnlySpan<char> GetCountedString(ReadOnlySpan<char> name)
        {
            if (!TryGetCountedString(name, out ReadOnlySpan<char> value))
            {
                ThrowMissing(name);
            }

            return value;
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

            // krabs::parser::parse requires sizeof(T) == propInfo.length_ exactly. Accepting
            // a wider property would silently truncate, and the C++/CLI surface reports that
            // as a failed parse rather than a value.
            if (raw.Length != size)
            {
                return false;
            }

            pointer = (byte*)Unsafe.AsPointer(ref MemoryMarshal.GetReference(raw));
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

        private static void ThrowMissing(ReadOnlySpan<char> name)
        {
            // C++/CLI wraps every parse failure as ParserException, and callers written
            // against it match on that exact type, so the port raises it directly rather
            // than a subclass.
            throw new ParserException("Could not find property in event schema: " + name.ToString());
        }
    }
}
