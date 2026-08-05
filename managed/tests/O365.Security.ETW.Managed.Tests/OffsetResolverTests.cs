using System;
using Microsoft.O365.Security.ETW.Interop;
using Microsoft.O365.Security.ETW.Schema;
using Xunit;

namespace Microsoft.O365.Security.ETW.Tests
{
    /// <summary>
    /// Offset resolution against a schema containing a property this implementation cannot
    /// size, which is what a caller reading properties out of order can run into.
    /// </summary>
    /// <remarks>
    /// Offsets are memoised behind a high-water mark, so reading a late property and then an
    /// early one costs a single walk rather than two. That memoisation must not become a way
    /// for a property that fails to decode to take working ones down with it: krabs resolves
    /// every offset from scratch on each access and so cannot have that problem, and the port
    /// has to behave the same.
    ///
    /// <see cref="OffsetResolverDifferentialTests"/> makes the same guarantee generally, over
    /// generated schemas. These cases pin the specific shape that regressed.
    /// </remarks>
    public unsafe class OffsetResolverTests : IDisposable
    {
        /// <summary>first (UInt32), middle (a struct, which this implementation will not size), last (UInt32).</summary>
        private readonly SchemaBlob _schema;
        private readonly SyntheticRecord _record;

        public OffsetResolverTests()
        {
            _schema = new SchemaBlobBuilder()
                .Fixed("first", TdhInType.UInt32, 4)
                .Struct("middle")
                .Fixed("last", TdhInType.UInt32, 4)
                .Build();

            _record = new SyntheticRecord(new byte[12]);
        }

        [Fact]
        public void ResolvesOffsetsBeforeTheUndecodableProperty()
        {
            OffsetResolver offsets = Resolver();

            Assert.Equal(0, offsets.GetOffset(0));
            Assert.Equal(4, offsets.GetOffset(1));
        }

        [Fact]
        public void DoesNotResolveOffsetsAfterTheUndecodableProperty()
        {
            OffsetResolver offsets = Resolver();

            Assert.Equal(-1, offsets.GetOffset(2));
        }

        /// <summary>
        /// The out-of-order case: a caller reads a property beyond the struct, then one before
        /// it. The second read is schema-known and must still resolve.
        /// </summary>
        [Fact]
        public void ReadingPastAnUndecodablePropertyLeavesEarlierOnesReadable()
        {
            OffsetResolver offsets = Resolver();

            Assert.Equal(-1, offsets.GetOffset(2));

            Assert.Equal(0, offsets.GetOffset(0));
            Assert.Equal(4, offsets.GetOffset(1));
        }

        private OffsetResolver Resolver()
        {
            var offsets = new OffsetResolver();
            offsets.Begin(_record.Record, _schema.Entry);
            return offsets;
        }

        public void Dispose()
        {
            _schema.Dispose();
            _record.Dispose();
        }
    }
}
