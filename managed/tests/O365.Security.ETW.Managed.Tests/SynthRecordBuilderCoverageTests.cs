using System;
using Microsoft.O365.Security.ETW;
using Microsoft.O365.Security.ETW.Testing;
using Xunit;

namespace Microsoft.O365.Security.ETW.Tests
{
    /// <summary>
    /// Covers synthetic records whose schemas are declared entirely by the test.
    /// </summary>
    /// <remarks>
    /// These assertions exercise the layout decisions made by <see cref="RecordBuilder"/>:
    /// fixed-width CLR values, SYSTEMTIME, schema-sized strings and padding for properties a
    /// caller deliberately leaves unfilled.
    /// </remarks>
    public class SynthRecordBuilderCoverageTests
    {
        private static readonly Guid ProviderId = Guid.Parse("d2a15c30-33a4-4f68-9e1a-8f0d33605b71");

        private delegate void RefAssert(in EventRecordRef record);

        [Fact]
        public void SystemTimeIsWrittenAsEightLittleEndianFields()
        {
            var when = new DateTime(2026, 8, 19, 15, 49, 3, 366, DateTimeKind.Utc);
            EventSchema schema = EventSchema
                .Create("Contoso-SystemTime", ProviderId, id: 1, version: 0)
                .SystemTime("When")
                .UInt32("Status");

            using (EventSchema.Use(schema))
            using (var builder = new RecordBuilder(ProviderId, id: 1, version: 0))
            {
                builder.AddSystemTime("When", when);
                builder.AddValue("Status", 0xAABBCCDDu);

                Push(
                    builder.Pack(),
                    (in EventRecordRef record) =>
                    {
                        Assert.True(record.TryGetRaw("When".AsSpan(), out ReadOnlySpan<byte> raw));
                        Assert.Equal(16, raw.Length);
                        Assert.Equal((ushort)when.Year, ReadUInt16(raw, 0));
                        Assert.Equal((ushort)when.Month, ReadUInt16(raw, 2));
                        Assert.Equal((ushort)when.DayOfWeek, ReadUInt16(raw, 4));
                        Assert.Equal((ushort)when.Day, ReadUInt16(raw, 6));
                        Assert.Equal((ushort)when.Hour, ReadUInt16(raw, 8));
                        Assert.Equal((ushort)when.Minute, ReadUInt16(raw, 10));
                        Assert.Equal((ushort)when.Second, ReadUInt16(raw, 12));
                        Assert.Equal((ushort)when.Millisecond, ReadUInt16(raw, 14));
                    },
                    record =>
                    {
                        Assert.Equal(when, record.GetDateTime("When"));
                        Assert.Equal(0xAABBCCDDu, record.GetUInt32("Status"));
                    });
            }
        }

        [Fact]
        public void AddValueWritesEachSupportedClrValueWithTheMatchingInType()
        {
            Guid id = Guid.Parse("79f73cf7-0759-421d-bf6f-e8e5c3b86328");
            EventSchema schema = EventSchema
                .Create("Contoso-Fixed-Values", ProviderId, id: 2, version: 0)
                .Int8("I8")
                .UInt8("U8")
                .Int16("I16")
                .UInt16("U16")
                .Int32("I32")
                .UInt32("U32")
                .Int64("I64")
                .UInt64("U64")
                .Float("Single")
                .Double("Double")
                .Guid("Id");

            using (EventSchema.Use(schema))
            using (var builder = new RecordBuilder(ProviderId, id: 2, version: 0))
            {
                builder.AddValue("I8", (sbyte)-5);
                builder.AddValue("U8", (byte)250);
                builder.AddValue("I16", (short)-1234);
                builder.AddValue("U16", (ushort)54321);
                builder.AddValue("I32", -123456789);
                builder.AddValue("U32", 3456789012u);
                builder.AddValue("I64", -1234567890123456789L);
                builder.AddValue("U64", 12345678901234567890ul);
                builder.AddValue("Single", 12.5f);
                builder.AddValue("Double", -9876.25d);
                builder.AddValue("Id", id);

                Push(builder.Pack(), (in EventRecordRef record) =>
                {
                    Assert.True(record.TryGetInt8("I8".AsSpan(), out sbyte i8));
                    Assert.Equal((sbyte)-5, i8);
                    Assert.True(record.TryGetUInt8("U8".AsSpan(), out byte u8));
                    Assert.Equal((byte)250, u8);
                    Assert.True(record.TryGetInt16("I16".AsSpan(), out short i16));
                    Assert.Equal((short)-1234, i16);
                    Assert.True(record.TryGetUInt16("U16".AsSpan(), out ushort u16));
                    Assert.Equal((ushort)54321, u16);
                    Assert.True(record.TryGetInt32("I32".AsSpan(), out int i32));
                    Assert.Equal(-123456789, i32);
                    Assert.True(record.TryGetUInt32("U32".AsSpan(), out uint u32));
                    Assert.Equal(3456789012u, u32);
                    Assert.True(record.TryGetInt64("I64".AsSpan(), out long i64));
                    Assert.Equal(-1234567890123456789L, i64);
                    Assert.True(record.TryGetUInt64("U64".AsSpan(), out ulong u64));
                    Assert.Equal(12345678901234567890ul, u64);
                    Assert.True(record.TryGetGuid("Id".AsSpan(), out Guid readId));
                    Assert.Equal(id, readId);
                    Assert.True(record.TryGetRaw("Single".AsSpan(), out ReadOnlySpan<byte> single));
                    Assert.Equal(12.5f, BitConverter.ToSingle(single.ToArray(), 0));
                    Assert.True(record.TryGetRaw("Double".AsSpan(), out ReadOnlySpan<byte> dbl));
                    Assert.Equal(-9876.25d, BitConverter.ToDouble(dbl.ToArray(), 0));
                });
            }
        }

        [Fact]
        public void UnfilledPropertiesPadByTheWidthTheReaderWillConsume()
        {
            EventSchema schema = EventSchema
                .Create("Contoso-Unfilled-Widths", ProviderId, id: 3, version: 0)
                .UnicodeString("Unicode")
                .AnsiString("Ansi")
                .Int8("I8")
                .UInt8("U8")
                .Int16("I16")
                .UInt16("U16")
                .Int32("I32")
                .UInt32("U32")
                .Int64("I64")
                .UInt64("U64")
                .Float("Single")
                .Double("Double")
                .Boolean("Bool")
                .Binary("Binary", length: 1)
                .Guid("Guid")
                .Pointer("Pointer")
                .FileTime("FileTime")
                .SystemTime("SystemTime")
                .Sid("Sid")
                .HexInt32("Hex32")
                .HexInt64("Hex64")
                .UInt32("Sentinel");

            using (EventSchema.Use(schema))
            using (var builder = new RecordBuilder(ProviderId, id: 3, version: 0))
            {
                builder.Header.Flags = (ushort)EventHeaderFlags.HEADER_32_BIT;
                builder.AddValue("Sentinel", 0x11223344u);

                Push(builder.PackIncomplete(), (in EventRecordRef record) =>
                {
                    AssertRawLength(record, "Unicode", 2);
                    AssertRawLength(record, "Ansi", 1);
                    AssertRawLength(record, "I8", 1);
                    AssertRawLength(record, "U8", 1);
                    AssertRawLength(record, "I16", 2);
                    AssertRawLength(record, "U16", 2);
                    AssertRawLength(record, "I32", 4);
                    AssertRawLength(record, "U32", 4);
                    AssertRawLength(record, "I64", 8);
                    AssertRawLength(record, "U64", 8);
                    AssertRawLength(record, "Single", 4);
                    AssertRawLength(record, "Double", 8);
                    AssertRawLength(record, "Bool", 4);
                    AssertRawLength(record, "Binary", 1);
                    AssertRawLength(record, "Guid", 16);
                    AssertRawLength(record, "Pointer", 4);
                    AssertRawLength(record, "FileTime", 8);
                    AssertRawLength(record, "SystemTime", 16);
                    AssertRawLength(record, "Sid", 8);
                    AssertRawLength(record, "Hex32", 4);
                    AssertRawLength(record, "Hex64", 8);
                    Assert.True(record.TryGetUInt32("Sentinel".AsSpan(), out uint sentinel));
                    Assert.Equal(0x11223344u, sentinel);
                });
            }
        }

        [Theory]
        [InlineData(1)]
        [InlineData(2)]
        [InlineData(4)]
        [InlineData(8)]
        public void LengthPropertiesOfEveryUnsignedWidthCanSizeAnsiStrings(int width)
        {
            EventSchema schema = EventSchema.Create("Contoso-Dynamic-Length", ProviderId, id: 10 + width, version: 0);
            switch (width)
            {
                case 1: schema.UInt8("Length"); break;
                case 2: schema.UInt16("Length"); break;
                case 4: schema.UInt32("Length"); break;
                case 8: schema.UInt64("Length"); break;
            }

            schema.AnsiString("Text", lengthFrom: "Length").UInt32("Status");

            using (EventSchema.Use(schema))
            using (var builder = new RecordBuilder(ProviderId, id: 10 + width, version: 0))
            {
                switch (width)
                {
                    case 1: builder.AddValue("Length", (byte)3); break;
                    case 2: builder.AddValue("Length", (ushort)3); break;
                    case 4: builder.AddValue("Length", 3u); break;
                    case 8: builder.AddValue("Length", 3ul); break;
                }

                builder.AddAnsiString("Text", "abc");
                builder.AddValue("Status", 17u);

                Push(builder.Pack(), (in EventRecordRef record) =>
                {
                    Assert.True(record.TryGetAnsiStringBytes("Text".AsSpan(), out ReadOnlySpan<byte> text));
                    Assert.Equal(new byte[] { (byte)'a', (byte)'b', (byte)'c' }, text.ToArray());
                    Assert.True(record.TryGetUInt32("Status".AsSpan(), out uint status));
                    Assert.Equal(17u, status);
                });
            }
        }

        [Fact]
        public void DynamicStringLengthMismatchIsRejectedWithThePropertyNames()
        {
            EventSchema schema = EventSchema
                .Create("Contoso-Length-Mismatch", ProviderId, id: 4, version: 0)
                .UInt16("Length")
                .UnicodeString("Text", lengthFrom: "Length");

            using (EventSchema.Use(schema))
            using (var builder = new RecordBuilder(ProviderId, id: 4, version: 0))
            {
                builder.AddValue("Length", (ushort)4);
                builder.AddUnicodeString("Text", "hello");

                var error = Assert.Throws<ArgumentException>(() => builder.Pack());
                Assert.Contains("Text", error.Message);
                Assert.Contains("Length", error.Message);
                Assert.Contains("Property Text is 5 long but Length, which the schema uses to size it, was given 4.", error.Message);
            }
        }

        [Fact]
        public void SidValuesAreValidatedAndClonedBeforePacking()
        {
            byte[] sid =
            {
                0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
                0x12, 0x00, 0x00, 0x00,
            };

            EventSchema schema = EventSchema
                .Create("Contoso-Sid", ProviderId, id: 5, version: 0)
                .Sid("Owner")
                .UInt32("Status");

            using (EventSchema.Use(schema))
            using (var builder = new RecordBuilder(ProviderId, id: 5, version: 0))
            {
                builder.AddSid("Owner", sid);
                sid[8] = 0xFF;
                builder.AddValue("Status", 9u);

                Push(builder.Pack(), (in EventRecordRef record) =>
                {
                    Assert.True(record.TryGetRaw("Owner".AsSpan(), out ReadOnlySpan<byte> raw));
                    Assert.Equal(0x12, raw[8]);
                    Assert.True(record.TryGetUInt32("Status".AsSpan(), out uint status));
                    Assert.Equal(9u, status);
                });
            }
        }

        [Fact]
        public void NullSidIsRejectedWithTheValueParameterName()
        {
            using (var builder = new RecordBuilder(ProviderId, id: 5, version: 0))
            {
                var error = Assert.Throws<ArgumentNullException>(() => builder.AddSid("Owner", null));
                Assert.Equal("value", error.ParamName);
            }
        }

        [Theory]
        [InlineData(new byte[] { 1, 0, 0, 0, 0, 0, 0 })]
        [InlineData(new byte[] { 1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0 })]
        public void MalformedSidIsRejectedWithThePropertyName(byte[] sid)
        {
            using (var builder = new RecordBuilder(ProviderId, id: 5, version: 0))
            {
                var error = Assert.Throws<ArgumentException>(() => builder.AddSid("Owner", sid));
                Assert.Null(error.ParamName);
                Assert.Contains("Owner", error.Message);
                Assert.Contains("well-formed binary SID", error.Message);
            }
        }

        private static void AssertRawLength(in EventRecordRef record, string name, int expected)
        {
            Assert.True(record.TryGetRaw(name.AsSpan(), out ReadOnlySpan<byte> raw));
            Assert.Equal(expected, raw.Length);
        }

        private static ushort ReadUInt16(ReadOnlySpan<byte> bytes, int offset)
        {
            return (ushort)(bytes[offset] | (bytes[offset + 1] << 8));
        }

        private static void Push(SynthRecord record, RefAssert refAssert, Action<IEventRecord> compatAssert = null)
        {
            var filter = new EventFilter(Filter.AnyEvent());
            Exception failure = null;
            int refSeen = 0;
            int compatSeen = 0;

            filter.OnEventRef += (in EventRecordRef evt) =>
            {
                refSeen++;
                try
                {
                    refAssert(evt);
                }
                catch (Exception ex)
                {
                    failure ??= ex;
                }
            };

            if (compatAssert != null)
            {
                filter.OnEvent += evt =>
                {
                    compatSeen++;
                    try
                    {
                        compatAssert(evt);
                    }
                    catch (Exception ex)
                    {
                        failure ??= ex;
                    }
                };
            }

            using (var proxy = new Proxy(filter))
            using (record)
            {
                proxy.PushEvent(record);
            }

            Assert.Equal(1, refSeen);
            Assert.Equal(compatAssert == null ? 0 : 1, compatSeen);

            if (failure != null)
            {
                throw failure;
            }
        }
    }
}
