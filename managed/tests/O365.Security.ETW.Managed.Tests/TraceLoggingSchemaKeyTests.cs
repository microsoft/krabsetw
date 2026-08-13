using System;
using System.Runtime.InteropServices;
using Microsoft.O365.Security.ETW.Interop;
using Microsoft.O365.Security.ETW.Schema;
using Xunit;

namespace Microsoft.O365.Security.ETW.Tests
{
    /// <summary>
    /// Covers how the schema cache identifies a self-describing (TraceLogging) event.
    /// </summary>
    /// <remarks>
    /// A TraceLogging event carries its own schema, and native TraceLogging leaves
    /// EVENT_DESCRIPTOR.Id at 0 -- unlike EventSource, which assigns an id per call site. So
    /// for a native provider the descriptor is identical across every event, and the metadata
    /// block is the only thing that distinguishes one event's layout from another's.
    ///
    /// Keying on the event *name* alone was therefore not enough. Two failures were measured
    /// against a real native provider before this was fixed:
    ///
    /// - Two same-named events with different fields: the first schema was applied to both,
    ///   so one shape decoded as the other. 964 of 1434 events returned a wrong value for a
    ///   field that was present in both.
    /// - A rolling upgrade that appended a field: the old schema stayed cached and the new
    ///   field was never readable, 0 times out of 193.
    ///
    /// Which shape won was a race -- whichever event the trace happened to see first.
    /// </remarks>
    public unsafe class TraceLoggingSchemaKeyTests
    {
        /// <summary>
        /// Builds a TraceLogging metadata block: UINT16 size, one extension byte, a NUL
        /// terminated UTF-8 name, then opaque field descriptors.
        /// </summary>
        private static byte[] MetadataBlock(string name, params byte[] fields)
        {
            int size = 2 + 1 + name.Length + 1 + fields.Length;
            var block = new byte[size];

            block[0] = (byte)size;
            block[1] = (byte)(size >> 8);
            block[2] = 0x00;

            for (int i = 0; i < name.Length; i++)
            {
                block[3 + i] = (byte)name[i];
            }

            block[3 + name.Length] = 0x00;
            fields.CopyTo(block, 4 + name.Length);

            return block;
        }

        /// <summary>
        /// Pushes a record carrying <paramref name="metadata"/> through the cache. The
        /// descriptor is identical for every call, exactly as native TraceLogging emits it.
        /// </summary>
        private static void Push(SchemaCache cache, byte[] metadata)
        {
            fixed (byte* block = metadata)
            {
                var item = default(EVENT_HEADER_EXTENDED_DATA_ITEM);
                item.ExtType = NativeConstants.EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL;
                item.DataSize = (ushort)metadata.Length;
                item.DataPtr = (ulong)block;

                var record = default(EVENT_RECORD);
                record.EventHeader.ProviderId = Guid.Parse("6f2d4b81-3c5a-4e17-9b62-8d0f1a3e5c74");
                record.EventHeader.EventDescriptor.Id = 0;
                record.EventHeader.EventDescriptor.Version = 0;
                record.EventHeader.Flags = NativeConstants.EVENT_HEADER_FLAG_64_BIT_HEADER;
                record.ExtendedData = (IntPtr)(&item);
                record.ExtendedDataCount = 1;

                cache.Get(&record);
            }
        }

        [Fact]
        public void TwoShapesSharingANameGetSeparateEntries()
        {
            using (var cache = new SchemaCache())
            {
                byte[] shapeA = MetadataBlock("Ambiguous", 0x01, 0x04);
                byte[] shapeB = MetadataBlock("Ambiguous", 0x01, 0x04, 0x02, 0x08);

                Push(cache, shapeA);
                Push(cache, shapeB);

                Assert.Equal(2, cache.Misses);
            }
        }

        /// <summary>
        /// The rolling-upgrade case: the same event gains a field. Old and new emitters run
        /// side by side, so both layouts arrive under one descriptor.
        /// </summary>
        [Fact]
        public void AnUpgradedEventGetsItsOwnEntry()
        {
            using (var cache = new SchemaCache())
            {
                byte[] oldVersion = MetadataBlock("Upgraded", 0x01);
                byte[] newVersion = MetadataBlock("Upgraded", 0x01, 0x02);

                Push(cache, oldVersion);
                Push(cache, newVersion);
                Push(cache, oldVersion);

                Assert.Equal(2, cache.Misses);
            }
        }

        /// <summary>
        /// The same block must still hit, or every event would be a miss and the cache would
        /// be worthless.
        /// </summary>
        [Fact]
        public void RepeatsOfOneShapeShareAnEntry()
        {
            using (var cache = new SchemaCache())
            {
                byte[] shape = MetadataBlock("Repeated", 0x01, 0x04);

                for (int i = 0; i < 10; i++)
                {
                    Push(cache, shape);
                }

                Assert.Equal(1, cache.Misses);
            }
        }
    }
}
