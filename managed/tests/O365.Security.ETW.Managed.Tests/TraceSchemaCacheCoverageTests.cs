using System;
using Microsoft.O365.Security.ETW.Interop;
using Microsoft.O365.Security.ETW.Schema;
using Xunit;

namespace Microsoft.O365.Security.ETW.Tests
{
    /// <summary>
    /// Covers TraceLogging metadata parsing used by schema cache keys.
    /// </summary>
    public unsafe class TraceSchemaCacheCoverageTests
    {
        [Fact]
        public void TraceLoggingEventNameSkipsExtensionBytesAndStopsAtTerminator()
        {
            byte[] metadata =
            {
                0x0B, 0x00,
                0x81, 0x02,
                (byte)'N', (byte)'a', (byte)'m', (byte)'e', 0x00,
                0xAA, 0xBB
            };

            fixed (byte* block = metadata)
            {
                var item = stackalloc EVENT_HEADER_EXTENDED_DATA_ITEM[1];
                var record = RecordWithMetadata(block, metadata.Length, item);

                Assert.Equal("Name", Ascii(TraceLoggingMetadata.GetEventName(&record)));
                Assert.Equal(metadata, TraceLoggingMetadata.GetMetadata(&record).ToArray());
            }
        }

        [Fact]
        public void TraceLoggingEventNameUsesTheRestOfTheBlockWhenNoTerminatorExists()
        {
            byte[] metadata =
            {
                0x07, 0x00,
                0x00,
                (byte)'R', (byte)'e', (byte)'s', (byte)'t'
            };

            fixed (byte* block = metadata)
            {
                var item = stackalloc EVENT_HEADER_EXTENDED_DATA_ITEM[1];
                var record = RecordWithMetadata(block, metadata.Length, item);

                Assert.Equal("Rest", Ascii(TraceLoggingMetadata.GetEventName(&record)));
            }
        }

        [Fact]
        public void TraceLoggingMetadataRejectsMalformedBlocks()
        {
            byte[] tooSmall = { 0x01 };
            byte[] wrongSize = { 0x04, 0x00, 0x00 };
            byte[] extensionOnly = { 0x04, 0x00, 0x80, 0x80 };

            fixed (byte* small = tooSmall)
            fixed (byte* wrong = wrongSize)
            fixed (byte* extension = extensionOnly)
            {
                var smallItem = stackalloc EVENT_HEADER_EXTENDED_DATA_ITEM[1];
                var wrongItem = stackalloc EVENT_HEADER_EXTENDED_DATA_ITEM[1];
                var extensionItem = stackalloc EVENT_HEADER_EXTENDED_DATA_ITEM[1];
                var smallRecord = RecordWithMetadata(small, tooSmall.Length, smallItem);
                var wrongRecord = RecordWithMetadata(wrong, wrongSize.Length, wrongItem);
                var extensionRecord = RecordWithMetadata(extension, extensionOnly.Length, extensionItem);
                var noMetadata = default(EVENT_RECORD);

                Assert.True(TraceLoggingMetadata.GetMetadata(&smallRecord).IsEmpty);
                Assert.True(TraceLoggingMetadata.GetEventName(&smallRecord).IsEmpty);
                Assert.True(TraceLoggingMetadata.GetMetadata(&wrongRecord).IsEmpty);
                Assert.True(TraceLoggingMetadata.GetEventName(&extensionRecord).IsEmpty);
                Assert.True(TraceLoggingMetadata.GetEventName(&noMetadata).IsEmpty);
            }
        }

        [Fact]
        public void TraceLoggingMetadataFindsSchemaItemAfterOtherExtendedData()
        {
            byte[] metadata = { 0x06, 0x00, 0x00, (byte)'O', (byte)'k', 0x00 };

            fixed (byte* block = metadata)
            {
                var items = stackalloc EVENT_HEADER_EXTENDED_DATA_ITEM[2];
                var ignored = stackalloc byte[8];
                items[0].ExtType = NativeConstants.EVENT_HEADER_EXT_TYPE_PROCESS_START_KEY;
                items[0].DataSize = 8;
                items[0].DataPtr = (ulong)ignored;
                items[1].ExtType = NativeConstants.EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL;
                items[1].DataSize = (ushort)metadata.Length;
                items[1].DataPtr = (ulong)block;

                var record = default(EVENT_RECORD);
                record.ExtendedData = (IntPtr)items;
                record.ExtendedDataCount = 2;

                Assert.Equal("Ok", Ascii(TraceLoggingMetadata.GetEventName(&record)));
            }
        }

        private static EVENT_RECORD RecordWithMetadata(byte* metadata, int length, EVENT_HEADER_EXTENDED_DATA_ITEM* item)
        {
            item[0].ExtType = NativeConstants.EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL;
            item[0].DataSize = (ushort)length;
            item[0].DataPtr = (ulong)metadata;

            var record = default(EVENT_RECORD);
            record.ExtendedData = (IntPtr)item;
            record.ExtendedDataCount = 1;
            return record;
        }

        private static string Ascii(ReadOnlySpan<byte> value)
        {
            char[] chars = new char[value.Length];
            for (int i = 0; i < value.Length; i++)
            {
                chars[i] = (char)value[i];
            }

            return new string(chars);
        }
    }
}
