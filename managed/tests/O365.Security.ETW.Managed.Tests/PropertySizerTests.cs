using Microsoft.O365.Security.ETW.Interop;
using Microsoft.O365.Security.ETW.Schema;
using Xunit;

namespace Microsoft.O365.Security.ETW.Tests
{
    /// <summary>
    /// The managed counterpart of tests\krabstests\test_size_provider.cpp. Both suites assert
    /// the same tdh.h documented sizing rules, so a divergence between the two implementations
    /// shows up as one suite failing.
    /// </summary>
    public unsafe class PropertySizerTests
    {
        private const int Pointer64 = 8;
        private const int Pointer32 = 4;

        [Fact]
        public void FixedLengthUnicodeStringLengthIsACountOfWchars()
        {
            // tdh.h, TDH_INTYPE_UNICODESTRING: epi.length is the length in WCHARs.
            Assert.Equal(
                16,
                PropertySizer.TryGetFixedSize(
                    flags: 0,
                    inType: (ushort)TdhInType.UnicodeString,
                    outType: (ushort)TdhOutType.String,
                    length: 8,
                    count: 1,
                    pointerSize: Pointer64));
        }

        [Fact]
        public void FixedLengthAnsiStringLengthIsACountOfBytes()
        {
            Assert.Equal(
                8,
                PropertySizer.TryGetFixedSize(
                    flags: 0,
                    inType: (ushort)TdhInType.AnsiString,
                    outType: (ushort)TdhOutType.String,
                    length: 8,
                    count: 1,
                    pointerSize: Pointer64));
        }

        [Fact]
        public void FixedLengthBinaryLengthIsACountOfBytes()
        {
            Assert.Equal(
                8,
                PropertySizer.TryGetFixedSize(
                    flags: 0,
                    inType: (ushort)TdhInType.Binary,
                    outType: (ushort)TdhOutType.HexBinary,
                    length: 8,
                    count: 1,
                    pointerSize: Pointer64));
        }

        [Fact]
        public void PointerSizeComesFromTheRecordPointerWidth()
        {
            Assert.Equal(
                8,
                PropertySizer.TryGetFixedElementSize(
                    (ushort)TdhInType.Pointer, (ushort)TdhOutType.HexInt64, PropertySizer.LengthUnspecified, Pointer64));

            Assert.Equal(
                4,
                PropertySizer.TryGetFixedElementSize(
                    (ushort)TdhInType.Pointer, (ushort)TdhOutType.HexInt64, PropertySizer.LengthUnspecified, Pointer32));
        }

        [Fact]
        public void LengthlessBinaryIsOnlySizeableAsAnIpv6Address()
        {
            Assert.Equal(
                16,
                PropertySizer.TryGetFixedElementSize(
                    (ushort)TdhInType.Binary, (ushort)TdhOutType.Ipv6, PropertySizer.LengthUnspecified, Pointer64));

            Assert.Equal(
                -1,
                PropertySizer.TryGetFixedElementSize(
                    (ushort)TdhInType.Binary, (ushort)TdhOutType.HexBinary, PropertySizer.LengthUnspecified, Pointer64));
        }

        [Fact]
        public void NullTerminatedUnicodeStringIsMeasuredFromThePayload()
        {
            byte[] payload = Utf16("abc\0");

            fixed (byte* p = payload)
            {
                Assert.Equal(
                    8,
                    PropertySizer.GetRuntimeSize(
                        (ushort)TdhInType.UnicodeString,
                        (ushort)TdhOutType.String,
                        PropertySizer.LengthUnspecified,
                        count: 1,
                        pointerSize: Pointer64,
                        data: p,
                        remaining: payload.Length));
            }
        }

        [Fact]
        public void UnterminatedUnicodeStringStopsAtTheEndOfTheRecord()
        {
            byte[] payload = Utf16("abc");

            fixed (byte* p = payload)
            {
                Assert.Equal(
                    6,
                    PropertySizer.GetRuntimeSize(
                        (ushort)TdhInType.UnicodeString,
                        (ushort)TdhOutType.String,
                        PropertySizer.LengthUnspecified,
                        count: 1,
                        pointerSize: Pointer64,
                        data: p,
                        remaining: payload.Length));
            }
        }

        /// <summary>
        /// A schema that specifies length zero describes an empty field, which is not the
        /// same as a schema that specifies no length at all.
        /// </summary>
        [Fact]
        public void ASpecifiedLengthOfZeroIsAnEmptyField()
        {
            byte[] payload = Utf16("abc\0");

            fixed (byte* p = payload)
            {
                Assert.Equal(
                    0,
                    PropertySizer.GetRuntimeSize(
                        (ushort)TdhInType.UnicodeString,
                        (ushort)TdhOutType.String,
                        length: 0,
                        count: 1,
                        pointerSize: Pointer64,
                        data: p,
                        remaining: payload.Length));
            }
        }

        [Fact]
        public void CountedStringsCarryALittleEndianByteCount()
        {
            byte[] payload = { 0x06, 0x00, (byte)'a', 0, (byte)'b', 0, (byte)'c', 0, 0xFF };

            fixed (byte* p = payload)
            {
                Assert.Equal(
                    8,
                    PropertySizer.GetRuntimeSize(
                        (ushort)TdhInType.CountedString,
                        (ushort)TdhOutType.String,
                        PropertySizer.LengthUnspecified,
                        count: 1,
                        pointerSize: Pointer64,
                        data: p,
                        remaining: payload.Length));
            }
        }

        [Fact]
        public void ReversedCountedStringsCarryABigEndianByteCount()
        {
            byte[] payload = { 0x00, 0x06, (byte)'a', 0, (byte)'b', 0, (byte)'c', 0, 0xFF };

            fixed (byte* p = payload)
            {
                Assert.Equal(
                    8,
                    PropertySizer.GetRuntimeSize(
                        (ushort)TdhInType.ReversedCountedString,
                        (ushort)TdhOutType.String,
                        PropertySizer.LengthUnspecified,
                        count: 1,
                        pointerSize: Pointer64,
                        data: p,
                        remaining: payload.Length));
            }
        }

        [Fact]
        public void AnOverlongCountedStringIsRejectedRatherThanRunningOffTheEnd()
        {
            byte[] payload = { 0xFF, 0xFF, (byte)'a', 0 };

            fixed (byte* p = payload)
            {
                Assert.Equal(
                    -1,
                    PropertySizer.GetRuntimeSize(
                        (ushort)TdhInType.CountedString,
                        (ushort)TdhOutType.String,
                        PropertySizer.LengthUnspecified,
                        count: 1,
                        pointerSize: Pointer64,
                        data: p,
                        remaining: payload.Length));
            }
        }

        /// <summary>
        /// A WBEMSID is an SE_TOKEN_USER whose prefix width comes from the producing
        /// process, not from ours.
        /// </summary>
        [Fact]
        public void WbemSidPrefixIsSizedFromTheRecordPointerWidth()
        {
            // Revision 1, one sub authority, six authority bytes, one 4-byte sub authority.
            byte[] sid = { 1, 1, 0, 0, 0, 0, 0, 5, 0x12, 0x00, 0x00, 0x00 };

            byte[] wide = new byte[16 + sid.Length];
            sid.CopyTo(wide, 16);

            byte[] narrow = new byte[8 + sid.Length];
            sid.CopyTo(narrow, 8);

            fixed (byte* p = wide)
            {
                Assert.Equal(
                    16 + 12,
                    PropertySizer.GetRuntimeSize(
                        (ushort)TdhInType.WbemSid,
                        0,
                        PropertySizer.LengthUnspecified,
                        count: 1,
                        pointerSize: Pointer64,
                        data: p,
                        remaining: wide.Length));
            }

            fixed (byte* p = narrow)
            {
                Assert.Equal(
                    8 + 12,
                    PropertySizer.GetRuntimeSize(
                        (ushort)TdhInType.WbemSid,
                        0,
                        PropertySizer.LengthUnspecified,
                        count: 1,
                        pointerSize: Pointer32,
                        data: p,
                        remaining: narrow.Length));
            }
        }

        private static byte[] Utf16(string value)
        {
            var bytes = new byte[value.Length * 2];
            for (int i = 0; i < value.Length; i++)
            {
                bytes[i * 2] = (byte)value[i];
                bytes[(i * 2) + 1] = (byte)(value[i] >> 8);
            }

            return bytes;
        }
    }
}
