using System;
using Microsoft.O365.Security.ETW.Interop;
using Microsoft.O365.Security.ETW.Schema;
using Xunit;

namespace Microsoft.O365.Security.ETW.Tests
{
    /// <summary>
    /// Covers schema sizing and offset paths for malformed and payload-dependent layouts.
    /// </summary>
    public unsafe class TraceSchemaSizingCoverageTests
    {
        private const int Pointer64 = 8;

        [Fact]
        public void FixedSizerRejectsCustomSchemaAndOversizedProducts()
        {
            Assert.Equal(
                -1,
                PropertySizer.TryGetFixedSize(
                    NativeConstants.PropertyHasCustomSchema,
                    (ushort)TdhInType.UInt32,
                    0,
                    length: 4,
                    count: 1,
                    pointerSize: Pointer64));

            Assert.Equal(
                -1,
                PropertySizer.TryGetFixedSize(
                    0,
                    (ushort)TdhInType.UnicodeString,
                    (ushort)TdhOutType.String,
                    length: 32768,
                    count: 2,
                    pointerSize: Pointer64));
        }

        [Fact]
        public void RuntimeSizerHandlesEmptyArraysAndInvalidBounds()
        {
            byte[] payload = { 1, 2, 3 };

            fixed (byte* p = payload)
            {
                Assert.Equal(
                    0,
                    PropertySizer.GetRuntimeSize(
                        (ushort)TdhInType.UInt32, 0, 4, 0, Pointer64, p, payload.Length));

                Assert.Equal(
                    -1,
                    PropertySizer.GetRuntimeSize(
                        (ushort)TdhInType.UInt32, 0, 4, -1, Pointer64, p, payload.Length));

                Assert.Equal(
                    -1,
                    PropertySizer.GetRuntimeSize(
                        (ushort)TdhInType.UInt32, 0, 4, 1, Pointer64, p, -1));
            }
        }

        [Fact]
        public void RuntimeSizerCoversDocumentedVariableWidthTypes()
        {
            byte[] ansi = { (byte)'a', (byte)'b', 0, 0x7F };
            byte[] nonNullAnsi = { (byte)'a', (byte)'b' };
            byte[] manifestBinary = { 0x03, 0x00, 1, 2, 3 };
            byte[] hexDump = { 0x02, 0x00, 0x00, 0x00, 0xAA, 0xBB };
            byte[] sid = { 1, 0, 0, 0, 0, 0, 0, 5 };

            fixed (byte* a = ansi)
            fixed (byte* n = nonNullAnsi)
            fixed (byte* m = manifestBinary)
            fixed (byte* h = hexDump)
            fixed (byte* s = sid)
            {
                Assert.Equal(3, PropertySizer.GetRuntimeSize((ushort)TdhInType.AnsiString, 0, -1, 1, Pointer64, a, ansi.Length));
                Assert.Equal(2, PropertySizer.GetRuntimeSize((ushort)TdhInType.NonNullTerminatedAnsiString, 0, -1, 1, Pointer64, n, nonNullAnsi.Length));
                Assert.Equal(5, PropertySizer.GetRuntimeSize((ushort)TdhInType.ManifestCountedBinary, 0, -1, 1, Pointer64, m, manifestBinary.Length));
                Assert.Equal(6, PropertySizer.GetRuntimeSize((ushort)TdhInType.HexDump, 0, -1, 1, Pointer64, h, hexDump.Length));
                Assert.Equal(8, PropertySizer.GetRuntimeSize((ushort)TdhInType.Sid, 0, -1, 1, Pointer64, s, sid.Length));
                Assert.Equal(-1, PropertySizer.GetRuntimeSize((ushort)TdhInType.Sid, 0, -1, 1, Pointer64, s, 7));
            }
        }

        [Fact]
        public void OffsetResolverRejectsMissingTablesAndInvalidIndexes()
        {
            using (var record = new SyntheticRecord(new byte[0]))
            {
                var resolver = new OffsetResolver();
                resolver.Begin(record.Record, new SchemaEntry(NativeConstants.ERROR_NOT_FOUND, null));

                Assert.Equal(-1, resolver.GetOffset(0));
                Assert.Equal(-1, resolver.GetOffset(-1));
            }
        }

        [Fact]
        public void OffsetResolverUsesPayloadDerivedCounts()
        {
            using (SchemaBlob schema = new SchemaBlobBuilder()
                .Fixed("count", TdhInType.UInt8, 1)
                .Add(
                    "items",
                    TdhInType.UInt8,
                    TdhOutType.Null,
                    length: 1,
                    count: 0,
                    flags: NativeConstants.PropertyParamCount)
                .Fixed("tail", TdhInType.UInt16, 2)
                .Build())
            using (var record = new SyntheticRecord(new byte[] { 3, 10, 11, 12, 0x34, 0x12 }))
            {
                var resolver = new OffsetResolver();
                resolver.Begin(record.Record, schema.Entry);

                Assert.Equal(4, resolver.GetOffset(2));
            }
        }

        [Fact]
        public void OffsetResolverRejectsForwardDynamicLengthReferences()
        {
            using (SchemaBlob schema = new SchemaBlobBuilder()
                .ParamLength("value", TdhInType.AnsiString, lengthPropertyIndex: 1)
                .Fixed("tail", TdhInType.UInt16, 2)
                .Build())
            using (var record = new SyntheticRecord(new byte[] { (byte)'x', 0x34, 0x12 }))
            {
                var resolver = new OffsetResolver();
                resolver.Begin(record.Record, schema.Entry);

                Assert.Equal(-1, resolver.GetOffset(1));
                Assert.Equal(-1, resolver.GetOffset(2));
            }
        }
    }
}
