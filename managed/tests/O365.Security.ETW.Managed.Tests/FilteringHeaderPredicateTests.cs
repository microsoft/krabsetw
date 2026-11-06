using System;
using Microsoft.O365.Security.ETW.Testing;
using Xunit;

namespace Microsoft.O365.Security.ETW.Tests
{
    /// <summary>
    /// Covers filter factory predicates that read event headers and fixed-width payload
    /// properties.
    /// </summary>
    public class FilteringHeaderPredicateTests
    {
        private static readonly Guid ProviderId = Guid.Parse("1c6a06f6-399f-4b54-830c-a69d2d790a83");
        private static readonly Guid OtherProviderId = Guid.Parse("9f89974f-808c-4ee2-b678-091b2df2435a");

        [Fact]
        public void HeaderPredicatesMatchTheExpectedRecordFields()
        {
            using (EventSchema.Use(Declaration(ProviderId)))
            using (SynthRecord record = Record(ProviderId, id: 42, version: 3, opcode: 7, level: 5, count: 1234u, bytes: 9876543210ul))
            {
                Assert.Equal(PredicateTier.Header, Filter.AnyEvent().Tier);
                Assert.True(Filter.AnyEvent().Test(record));
                Assert.Equal(PredicateTier.Header, Filter.NoEvent().Tier);
                Assert.False(Filter.NoEvent().Test(record));
                Assert.True(Filter.EventIdIs(42).Test(record));
                Assert.False(Filter.EventIdIs(41).Test(record));
                Assert.Equal(PredicateTier.Header, Filter.EventOpcodeIs(7).Tier);
                Assert.True(Filter.EventOpcodeIs(7).Test(record));
                Assert.False(Filter.EventOpcodeIs(8).Test(record));
                Assert.True(Filter.EventVersionIs(3).Test(record));
                Assert.False(Filter.EventVersionIs(4).Test(record));
                Assert.Equal(PredicateTier.Header, Filter.EventLevelIs(5).Tier);
                Assert.True(Filter.EventLevelIs(5).Test(record));
                Assert.False(Filter.EventLevelIs(6).Test(record));
                Assert.True(Filter.ProcessIdIs(0).Test(record));
                Assert.False(Filter.ProcessIdIs(1).Test(record));
                Assert.Equal(PredicateTier.Header, Filter.ProviderIdIs(ProviderId).Tier);
                Assert.True(Filter.ProviderIdIs(ProviderId).Test(record));
                Assert.False(Filter.ProviderIdIs(OtherProviderId).Test(record));
                Assert.True(Filter.EventNameIs("FileOpened").Test(record));
                Assert.False(Filter.EventNameIs("fileopened").Test(record));
                Assert.True(Filter.EventNameIEquals("fileopened").Test(record));
            }
        }

        [Fact]
        public void UIntPropertyPredicatesMatchOnlyPresentEqualValues()
        {
            using (EventSchema.Use(Declaration(ProviderId)))
            using (SynthRecord record = Record(ProviderId, id: 42, version: 3, opcode: 7, level: 5, count: 1234u, bytes: 9876543210ul))
            {
                Assert.True(Filter.IsUInt32("Count", 1234u).Test(record));
                Assert.False(Filter.IsUInt32("Count", 1235u).Test(record));
                Assert.False(Filter.IsUInt32("Missing", 1234u).Test(record));

                Assert.True(Filter.IsUInt64("Bytes", 9876543210ul).Test(record));
                Assert.False(Filter.IsUInt64("Bytes", 9876543211ul).Test(record));
                Assert.False(Filter.IsUInt64("Missing", 9876543210ul).Test(record));
            }
        }

        [Fact]
        public void CustomPredicateDelegatesToTheSuppliedFunction()
        {
            using (EventSchema.Use(Declaration(ProviderId)))
            using (SynthRecord record = Record(ProviderId, id: 42, version: 3, opcode: 7, level: 5, count: 1234u, bytes: 9876543210ul))
            {
                Predicate predicate = Filter.Custom((in EventRecordRef evt) => evt.Id == 42);

                Assert.Equal(PredicateTier.Payload, predicate.Tier);
                Assert.True(predicate.Test(record));
            }
        }

        [Fact]
        public void FactoryMethodsValidateNullAndRangeArguments()
        {
            Assert.Throws<ArgumentNullException>(() => Filter.Not(null));
            Assert.Throws<ArgumentNullException>(() => Filter.Custom(null));
            Assert.Throws<ArgumentNullException>(() => Filter.EventNameIs(null));
            Assert.Throws<ArgumentNullException>(() => Filter.EventNameIEquals(null));
            Assert.Throws<ArgumentNullException>(() => Filter.IsUInt32(null, 1));
            Assert.Throws<ArgumentNullException>(() => Filter.IsUInt64(null, 1));
            Assert.Throws<OverflowException>(() => Filter.EventIdIs(ushort.MaxValue + 1));
            Assert.Throws<OverflowException>(() => Filter.EventOpcodeIs(byte.MaxValue + 1));
            Assert.Throws<OverflowException>(() => Filter.EventVersionIs(byte.MaxValue + 1));
            Assert.Throws<OverflowException>(() => Filter.EventLevelIs(byte.MaxValue + 1));
        }

        private static EventSchema Declaration(Guid providerId)
        {
            return EventSchema
                .Create("Filtering-Header-Predicate-Provider", providerId, id: 42, version: 3)
                .Named("FileOpened")
                .UInt32("Count")
                .UInt64("Bytes");
        }

        private static SynthRecord Record(Guid providerId, int id, int version, int opcode, int level, uint count, ulong bytes)
        {
            using (var builder = new RecordBuilder(providerId, id, version, opcode, level, keyword: 0, trimStringNullTerminator: false))
            {
                builder.AddValue("Count", count);
                builder.AddValue("Bytes", bytes);
                return builder.Pack();
            }
        }
    }
}
