using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using Microsoft.O365.Security.ETW.Interop;
using Microsoft.O365.Security.ETW.Testing;
using Xunit;

namespace Microsoft.O365.Security.ETW.Tests
{
    /// <summary>
    /// Covers the source-compatible <see cref="IEventRecord"/> adapter over synthetic records.
    /// </summary>
    public unsafe class CompatEventRecordAdapterTests
    {
        private static readonly Guid ProviderId = Guid.Parse("47d7bb5f-62a3-4e14-8b57-3d3758b78f55");
        private static readonly Guid ActivityId = Guid.Parse("3cb79747-0f0f-4d6d-9c84-b39a72617f50");

        [Fact]
        public void MetadataAndPropertiesReflectTheUnderlyingRecord()
        {
            WithRecord(record =>
            {
                Assert.Equal(100, record.Id);
                Assert.Equal(3, record.Opcode);
                Assert.Equal(1, record.Version);
                Assert.Equal(4, record.Level);
                Assert.Equal((ushort)EventHeaderFlags.EXTENDED_INFO, record.Flags);
                Assert.Equal(EventHeaderProperty.XML, record.EventProperty);
                Assert.Equal(4321u, record.ProcessId);
                Assert.Equal(8765u, record.ThreadId);
                Assert.Equal(ProviderId, record.ProviderId);
                Assert.Equal(ActivityId, record.ActivityId);
                Assert.True(record.UserDataLength > 0);
                Assert.NotEqual(IntPtr.Zero, record.UserData);
                Assert.Equal(DecodingSource.XMLFile, record.GetEventType());
                Assert.Equal("CompatEvent", record.Name);
                Assert.Equal("Contoso-Compat-Provider", record.ProviderName);
                Assert.Equal(DecodingSource.XMLFile, record.DecodingSource);

                List<Property> properties = record.Properties.ToList();
                Assert.Contains(properties, p => p.Name == "U32" && p.InType == (uint)TdhInType.UInt32 && p.Length == sizeof(uint));
                Assert.Contains(properties, p => p.Name == "IPv4" && p.InType == (uint)TdhInType.Binary && p.Length == 4);
                Assert.Contains(properties, p => p.Name == "Unicode" && p.OutType == (uint)TdhOutType.Null);

                byte[] userData = record.CopyUserData();
                Assert.Equal(record.UserDataLength, userData.Length);
                Assert.NotEmpty(userData);
            });
        }

        [Fact]
        public void StringAndIntegerAccessorsReturnValuesDefaultsAndMissingResults()
        {
            WithRecord(record =>
            {
                Assert.Equal("hello", record.GetUnicodeString("Unicode"));
                Assert.Equal("fallback", record.GetUnicodeString("Missing", "fallback"));
                Assert.True(record.TryGetUnicodeString("Unicode", out string unicode));
                Assert.Equal("hello", unicode);
                Assert.False(record.TryGetUnicodeString("Missing", out string missingUnicode));
                Assert.Null(missingUnicode);

                Assert.Equal("ansi", record.GetAnsiString("Ansi"));
                Assert.Equal("fallback", record.GetAnsiString("Missing", "fallback"));
                Assert.True(record.TryGetAnsiString("Ansi", out string ansi));
                Assert.Equal("ansi", ansi);
                Assert.False(record.TryGetAnsiString("Missing", out string missingAnsi));
                Assert.Null(missingAnsi);

                Assert.Equal("abcd", record.GetCountedString("Counted"));
                Assert.Equal("fallback", record.GetCountedString("Missing", "fallback"));
                Assert.True(record.TryGetCountedString("Counted", out string counted));
                Assert.Equal("abcd", counted);
                Assert.False(record.TryGetCountedString("Missing", out string missingCounted));
                Assert.Null(missingCounted);

                Assert.Equal(-5, record.GetInt8("I8"));
                Assert.Equal(7, record.GetInt8("Missing", 7));
                Assert.True(record.TryGetInt8("I8", out sbyte i8));
                Assert.Equal(-5, i8);

                Assert.Equal(250, record.GetUInt8("U8"));
                Assert.Equal(7, record.GetUInt8("Missing", 7));
                Assert.True(record.TryGetUInt8("U8", out byte u8));
                Assert.Equal(250, u8);

                Assert.Equal(-1234, record.GetInt16("I16"));
                Assert.Equal(7, record.GetInt16("Missing", 7));
                Assert.True(record.TryGetInt16("I16", out short i16));
                Assert.Equal(-1234, i16);

                Assert.Equal(54321, record.GetUInt16("U16"));
                Assert.Equal(7, record.GetUInt16("Missing", 7));
                Assert.True(record.TryGetUInt16("U16", out ushort u16));
                Assert.Equal(54321, u16);

                Assert.Equal(-123456, record.GetInt32("I32"));
                Assert.Equal(7, record.GetInt32("Missing", 7));
                Assert.True(record.TryGetInt32("I32", out int i32));
                Assert.Equal(-123456, i32);

                Assert.Equal(4000000000u, record.GetUInt32("U32"));
                Assert.Equal(7u, record.GetUInt32("Missing", 7u));
                Assert.True(record.TryGetUInt32("U32", out uint u32));
                Assert.Equal(4000000000u, u32);

                Assert.Equal(-1234567890123L, record.GetInt64("I64"));
                Assert.Equal(7L, record.GetInt64("Missing", 7L));
                Assert.True(record.TryGetInt64("I64", out long i64));
                Assert.Equal(-1234567890123L, i64);

                Assert.Equal(0x8877665544332211ul, record.GetUInt64("U64"));
                Assert.Equal(7ul, record.GetUInt64("Missing", 7ul));
                Assert.True(record.TryGetUInt64("U64", out ulong u64));
                Assert.Equal(0x8877665544332211ul, u64);
            });
        }

        [Fact]
        public void StructuredAccessorsReturnValuesDefaultsAndMissingResults()
        {
            var expectedFileTime = new DateTime(2024, 5, 6, 7, 8, 9, DateTimeKind.Utc);
            var expectedSystemTime = new DateTime(2025, 1, 2, 3, 4, 5, 6, DateTimeKind.Utc);
            var defaultAddress = IPAddress.Loopback;
            var defaultSocket = new SocketAddress(AddressFamily.InterNetwork, 16);

            WithRecord(record =>
            {
                Assert.Equal(new byte[] { 1, 2, 3, 4 }, record.GetBinary("Payload"));
                Assert.True(record.TryGetBinary("Payload", out byte[] binary));
                Assert.Equal(new byte[] { 1, 2, 3, 4 }, binary);
                binary[0] = 99;
                Assert.Equal(new byte[] { 1, 2, 3, 4 }, record.GetBinary("Payload"));
                Assert.False(record.TryGetBinary("Missing", out byte[] missingBinary));
                Assert.Null(missingBinary);

                Assert.Equal(IPAddress.Parse("192.0.2.7"), record.GetIPAddress("IPv4"));
                Assert.Equal(IPAddress.Parse("2001:db8::1"), record.GetIPAddress("IPv6"));
                Assert.Same(defaultAddress, record.GetIPAddress("Missing", defaultAddress));
                Assert.True(record.TryGetIPAddress("IPv4", out IPAddress ip));
                Assert.Equal(IPAddress.Parse("192.0.2.7"), ip);
                Assert.False(record.TryGetIPAddress("ShortBinary", out IPAddress shortIp));
                Assert.Null(shortIp);
                Assert.False(record.TryGetIPAddress("Unicode", out IPAddress wrongTypeIp));
                Assert.Null(wrongTypeIp);

                SocketAddress socket = record.GetSocketAddress("Socket");
                Assert.Equal(AddressFamily.InterNetwork, socket.Family);
                Assert.Equal(16, socket.Size);
                Assert.Equal(2, socket[0]);
                Assert.Equal(0, socket[1]);
                Assert.Same(defaultSocket, record.GetSocketAddress("Missing", defaultSocket));
                Assert.True(record.TryGetSocketAddress("Socket", out SocketAddress triedSocket));
                Assert.Equal(AddressFamily.InterNetwork, triedSocket.Family);
                Assert.False(record.TryGetSocketAddress("OneByte", out SocketAddress oneByteSocket));
                Assert.Null(oneByteSocket);
                Assert.False(record.TryGetSocketAddress("Missing", out SocketAddress missingSocket));
                Assert.Null(missingSocket);

                Assert.Equal(expectedFileTime, record.GetDateTime("FileTimeRaw"));
                Assert.Equal(expectedSystemTime, record.GetDateTime("SystemTimeRaw"));
                Assert.Equal(expectedFileTime, record.GetDateTime("Missing", expectedFileTime));
                Assert.True(record.TryGetDateTime("FileTimeRaw", out DateTime fileTime));
                Assert.Equal(expectedFileTime, fileTime);
                Assert.True(record.TryGetDateTime("ZeroFileTime", out DateTime zeroFileTime));
                Assert.Equal(DateTime.FromFileTimeUtc(0), zeroFileTime);
                Assert.False(record.TryGetDateTime("NegativeFileTime", out DateTime negativeFileTime));
                Assert.Equal(default, negativeFileTime);
                Assert.False(record.TryGetDateTime("InvalidSystemTime", out DateTime invalidSystemTime));
                Assert.Equal(default, invalidSystemTime);
                Assert.False(record.TryGetDateTime("ShortBinary", out DateTime shortDateTime));
                Assert.Equal(default, shortDateTime);
            });
        }

        [Fact]
        public void MissingRequiredAccessorsThrowParserException()
        {
            WithRecord(record =>
            {
                Assert.Throws<ParserException>(() => record.GetUnicodeString("Missing"));
                Assert.Throws<ParserException>(() => record.GetAnsiString("Missing"));
                Assert.Throws<ParserException>(() => record.GetCountedString("Missing"));
                Assert.Throws<ParserException>(() => record.GetInt8("Missing"));
                Assert.Throws<ParserException>(() => record.GetUInt8("Missing"));
                Assert.Throws<ParserException>(() => record.GetInt16("Missing"));
                Assert.Throws<ParserException>(() => record.GetUInt16("Missing"));
                Assert.Throws<ParserException>(() => record.GetInt32("Missing"));
                Assert.Throws<ParserException>(() => record.GetUInt32("Missing"));
                Assert.Throws<ParserException>(() => record.GetInt64("Missing"));
                Assert.Throws<ParserException>(() => record.GetUInt64("Missing"));
                Assert.Throws<ParserException>(() => record.GetBinary("Missing"));
                Assert.Throws<ParserException>(() => record.GetIPAddress("Missing"));
                Assert.Throws<ParserException>(() => record.GetSocketAddress("Missing"));
                Assert.Throws<ParserException>(() => record.GetDateTime("Missing"));
            });
        }

        [Fact]
        public void ExtendedDataAccessorsSurfaceBuilderItemsThroughTheAdapter()
        {
            var containerId = Guid.Parse("267bc684-2b8a-4e25-9643-5a6f4acbea0b");
            const ulong processStartKey = 0x0102030405060708ul;

            WithRecord(
                record =>
                {
                    Assert.True(record.TryGetContainerId(out Guid actualContainerId));
                    Assert.Equal(containerId, actualContainerId);
                    Assert.True(record.TryGetProcessStartKey(out ulong actualProcessStartKey));
                    Assert.Equal(processStartKey, actualProcessStartKey);
                    Assert.Empty(record.GetStackTrace());
                },
                builder =>
                {
                    builder.AddContainerId(containerId);
                    builder.AddProcessStartKey(processStartKey);
                });
        }

        private static EventSchema Schema()
        {
            return EventSchema
                .Create("Contoso-Compat-Provider", ProviderId, id: 100, version: 1)
                .Named("CompatEvent")
                .UInt8("U8")
                .Int8("I8")
                .UInt16("U16")
                .Int16("I16")
                .UInt32("U32")
                .Int32("I32")
                .UInt64("U64")
                .Int64("I64")
                .UnicodeString("Unicode")
                .AnsiString("Ansi")
                .UnicodeString("Counted")
                .Binary("Payload", length: 4)
                .Binary("IPv4", length: 4)
                .Binary("IPv6", length: 16)
                .Binary("Socket", length: 16)
                .Binary("ShortBinary", length: 3)
                .Binary("OneByte", length: 1)
                .Binary("FileTimeRaw", length: 8)
                .Binary("ZeroFileTime", length: 8)
                .Binary("NegativeFileTime", length: 8)
                .SystemTime("SystemTimeRaw")
                .Binary("InvalidSystemTime", length: 16);
        }

        private static void WithRecord(Action<IEventRecord> assertion, Action<RecordBuilder> configure = null)
        {
            using (EventSchema.Use(Schema()))
            using (var builder = new RecordBuilder(ProviderId, id: 100, version: 1, opcode: 3, level: 4, keyword: 0, trimStringNullTerminator: false))
            {
                builder.Header.Flags = (ushort)EventHeaderFlags.EXTENDED_INFO;
                AddPayload(builder);
                configure?.Invoke(builder);

                using (SynthRecord record = builder.Pack())
                {
                    record.Record->EventHeader.EventProperty = (ushort)EventHeaderProperty.XML;
                    record.Record->EventHeader.ProcessId = 4321;
                    record.Record->EventHeader.ThreadId = 8765;
                    record.Record->EventHeader.ActivityId = ActivityId;
                    Push(record, assertion);
                }
            }
        }

        private static void AddPayload(RecordBuilder builder)
        {
            var fileTime = new DateTime(2024, 5, 6, 7, 8, 9, DateTimeKind.Utc);
            var systemTime = new DateTime(2025, 1, 2, 3, 4, 5, 6, DateTimeKind.Utc);
            byte[] socket = new byte[16];
            socket[0] = (byte)AddressFamily.InterNetwork;
            socket[1] = 0;

            builder.AddValue("U8", (byte)250);
            builder.AddValue("I8", (sbyte)-5);
            builder.AddValue("U16", (ushort)54321);
            builder.AddValue("I16", (short)-1234);
            builder.AddValue("U32", 4000000000u);
            builder.AddValue("I32", -123456);
            builder.AddValue("U64", 0x8877665544332211ul);
            builder.AddValue("I64", -1234567890123L);
            builder.AddUnicodeString("Unicode", "hello");
            builder.AddAnsiString("Ansi", "ansi");
            builder.AddUnicodeString("Counted", "\u0008abcd");
            builder.AddBinary("Payload", new byte[] { 1, 2, 3, 4 });
            builder.AddBinary("IPv4", IPAddress.Parse("192.0.2.7").GetAddressBytes());
            builder.AddBinary("IPv6", IPAddress.Parse("2001:db8::1").GetAddressBytes());
            builder.AddBinary("Socket", socket);
            builder.AddBinary("ShortBinary", new byte[] { 1, 2, 3 });
            builder.AddBinary("OneByte", new byte[] { 1 });
            builder.AddBinary("FileTimeRaw", BitConverter.GetBytes(fileTime.ToFileTimeUtc()));
            builder.AddBinary("ZeroFileTime", BitConverter.GetBytes(0L));
            builder.AddBinary("NegativeFileTime", BitConverter.GetBytes(-1L));
            builder.AddSystemTime("SystemTimeRaw", systemTime);
            builder.AddBinary("InvalidSystemTime", InvalidSystemTimeBytes());
        }

        private static byte[] InvalidSystemTimeBytes()
        {
            byte[] bytes = new byte[16];
            WriteUInt16(bytes, 0, 2025);
            WriteUInt16(bytes, 2, 13);
            WriteUInt16(bytes, 6, 1);
            return bytes;
        }

        private static void WriteUInt16(byte[] bytes, int offset, ushort value)
        {
            bytes[offset] = (byte)value;
            bytes[offset + 1] = (byte)(value >> 8);
        }

        private static void Push(SynthRecord record, Action<IEventRecord> assertion)
        {
            var filter = new EventFilter(Filter.AnyEvent());
            Exception failure = null;
            int seen = 0;

            filter.OnEvent += evt =>
            {
                seen++;
                try
                {
                    assertion(evt);
                }
                catch (Exception ex)
                {
                    failure = ex;
                }
            };

            using (var proxy = new Proxy(filter))
            {
                proxy.PushEvent(record);
            }

            Assert.Equal(1, seen);
            if (failure != null)
            {
                throw failure;
            }
        }
    }
}
