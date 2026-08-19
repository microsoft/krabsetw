using System;
using System.Collections.Generic;
using Microsoft.O365.Security.ETW.Interop;
using Microsoft.O365.Security.ETW.Testing;
using Xunit;

namespace Microsoft.O365.Security.ETW.Tests
{
    /// <summary>
    /// Covers the compat extended-data reader against hand-shaped ETW extended-data items.
    /// </summary>
    public unsafe class CompatExtendedDataTests
    {
        private unsafe delegate void RecordAssertion(EVENT_RECORD* record);

        [Fact]
        public void BuilderPacksContainerIdAndProcessStartKeyInEtwShape()
        {
            var containerId = Guid.Parse("fda5517a-60e5-4b17-b996-becbf9f67c9d");
            const ulong processStartKey = 0x8877665544332211ul;

            var builder = new ExtendedDataBuilder();
            Assert.Equal(0, builder.Count);
            Assert.Null(builder.Pack());

            builder.AddContainerId(containerId);
            builder.AddProcessStartKey(processStartKey);

            using (SafeHGlobalHandle packed = builder.Pack()!)
            {
                var record = default(EVENT_RECORD);
                record.ExtendedData = packed.Pointer;
                record.ExtendedDataCount = (ushort)builder.Count;

                Assert.True(ExtendedData.TryGetContainerId(&record, out Guid actualContainerId));
                Assert.Equal(containerId, actualContainerId);

                Assert.True(ExtendedData.TryGetProcessStartKey(&record, out ulong actualProcessStartKey));
                Assert.Equal(processStartKey, actualProcessStartKey);

                var items = (EVENT_HEADER_EXTENDED_DATA_ITEM*)packed.Pointer;
                Assert.Equal(NativeConstants.EVENT_HEADER_EXT_TYPE_CONTAINER_ID, items[0].ExtType);
                Assert.Equal(36, items[0].DataSize);
                Assert.Equal(NativeConstants.EVENT_HEADER_EXT_TYPE_PROCESS_START_KEY, items[1].ExtType);
                Assert.Equal(sizeof(ulong), items[1].DataSize);
            }
        }

        [Fact]
        public void ContainerIdRejectsMissingTruncatedAndInvalidItems()
        {
            Assert.False(ExtendedData.TryGetContainerId(null, out Guid missingRecord));
            Assert.Equal(Guid.Empty, missingRecord);

            WithOneItem(
                extType: NativeConstants.EVENT_HEADER_EXT_TYPE_PROCESS_START_KEY,
                payload: new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 },
                record =>
                {
                    Assert.False(ExtendedData.TryGetContainerId(record, out Guid wrongType));
                    Assert.Equal(Guid.Empty, wrongType);
                });

            WithOneItem(
                extType: NativeConstants.EVENT_HEADER_EXT_TYPE_CONTAINER_ID,
                payload: new byte[] { (byte)'a', (byte)'b', (byte)'c' },
                record =>
                {
                    Assert.False(ExtendedData.TryGetContainerId(record, out Guid truncated));
                    Assert.Equal(Guid.Empty, truncated);
                });

            WithOneItem(
                extType: NativeConstants.EVENT_HEADER_EXT_TYPE_CONTAINER_ID,
                payload: System.Text.Encoding.ASCII.GetBytes(new string('z', 36)),
                record =>
                {
                    Assert.False(ExtendedData.TryGetContainerId(record, out Guid invalid));
                    Assert.Equal(Guid.Empty, invalid);
                });
        }

        [Fact]
        public void ProcessStartKeyRejectsMissingAndTruncatedItems()
        {
            WithOneItem(
                extType: NativeConstants.EVENT_HEADER_EXT_TYPE_CONTAINER_ID,
                payload: new byte[36],
                record =>
                {
                    Assert.False(ExtendedData.TryGetProcessStartKey(record, out ulong wrongType));
                    Assert.Equal(0ul, wrongType);
                });

            WithOneItem(
                extType: NativeConstants.EVENT_HEADER_EXT_TYPE_PROCESS_START_KEY,
                payload: new byte[] { 0x11, 0x22, 0x33 },
                record =>
                {
                    Assert.False(ExtendedData.TryGetProcessStartKey(record, out ulong truncated));
                    Assert.Equal(0ul, truncated);
                });
        }

        [Fact]
        public void StackTraceReadsThirtyTwoAndSixtyFourBitFrames()
        {
            byte[] stack64 =
            {
                0, 0, 0, 0, 0, 0, 0, 0,
                0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
                0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99,
            };

            byte[] stack32 =
            {
                0, 0, 0, 0, 0, 0, 0, 0,
                0x78, 0x56, 0x34, 0x12,
                0xef, 0xcd, 0xab, 0x90,
            };

            fixed (byte* stack64Data = stack64)
            fixed (byte* stack32Data = stack32)
            {
                EVENT_HEADER_EXTENDED_DATA_ITEM* items = stackalloc EVENT_HEADER_EXTENDED_DATA_ITEM[2];
                items[0].ExtType = NativeConstants.EVENT_HEADER_EXT_TYPE_STACK_TRACE64;
                items[0].DataSize = (ushort)stack64.Length;
                items[0].DataPtr = (ulong)stack64Data;
                items[1].ExtType = NativeConstants.EVENT_HEADER_EXT_TYPE_STACK_TRACE32;
                items[1].DataSize = (ushort)stack32.Length;
                items[1].DataPtr = (ulong)stack32Data;

                var record = default(EVENT_RECORD);
                record.ExtendedData = (IntPtr)items;
                record.ExtendedDataCount = 2;

                Assert.Equal(
                    new List<ulong>
                    {
                        0x1122334455667788ul,
                        0x99aabbccddeeff00ul,
                        0x12345678ul,
                        0x90abcdeful
                    },
                    ExtendedData.GetStackTrace(&record));
            }
        }

        [Fact]
        public void StackTraceSkipsNullEmptyAndTooSmallItems()
        {
            Assert.Empty(ExtendedData.GetStackTrace(null));

            byte* stackData = stackalloc byte[sizeof(ulong)];
            EVENT_HEADER_EXTENDED_DATA_ITEM* items = stackalloc EVENT_HEADER_EXTENDED_DATA_ITEM[2];
            items[0].ExtType = NativeConstants.EVENT_HEADER_EXT_TYPE_STACK_TRACE64;
            items[0].DataSize = sizeof(ulong);
            items[0].DataPtr = 0;
            items[1].ExtType = NativeConstants.EVENT_HEADER_EXT_TYPE_STACK_TRACE32;
            items[1].DataSize = sizeof(ulong);
            items[1].DataPtr = (ulong)stackData;

            var record = default(EVENT_RECORD);
            record.ExtendedData = (IntPtr)items;
            record.ExtendedDataCount = 2;

            Assert.Empty(ExtendedData.GetStackTrace(&record));
        }

        private static void WithOneItem(ushort extType, byte[] payload, RecordAssertion assertion)
        {
            fixed (byte* data = payload)
            {
                EVENT_HEADER_EXTENDED_DATA_ITEM item = default(EVENT_HEADER_EXTENDED_DATA_ITEM);
                item.ExtType = extType;
                item.DataSize = (ushort)payload.Length;
                item.DataPtr = (ulong)data;

                var record = default(EVENT_RECORD);
                record.ExtendedData = (IntPtr)(&item);
                record.ExtendedDataCount = 1;

                assertion(&record);
            }
        }
    }
}
