using System;
using Microsoft.O365.Security.ETW.Testing;
using Xunit;

namespace Microsoft.O365.Security.ETW.Tests
{
    /// <summary>
    /// Covers predicate composition, including short-circuiting and the compatibility
    /// operator method names exposed by the managed port.
    /// </summary>
    public class FilteringPredicateCompositionTests
    {
        private static readonly Guid ProviderId = Guid.Parse("b7db8f01-5405-480b-8a74-f37586912698");

        [Fact]
        public void AndShortCircuitsAfterAFalseHeaderPredicate()
        {
            int payloadReads = 0;
            Predicate predicate = Filter.EventIdIs(2).And(Filter.Custom((in EventRecordRef record) =>
            {
                payloadReads++;
                return true;
            }));

            using (EventSchema.Use(Declaration(1)))
            using (SynthRecord record = Record(1))
            {
                Assert.Equal(PredicateTier.Payload, predicate.Tier);
                Assert.False(predicate.Test(record));
                Assert.Equal(0, payloadReads);
            }
        }

        [Fact]
        public void OrShortCircuitsAfterATrueHeaderPredicate()
        {
            int payloadReads = 0;
            Predicate predicate = Filter.EventIdIs(1).Or(Filter.Custom((in EventRecordRef record) =>
            {
                payloadReads++;
                return false;
            }));

            using (EventSchema.Use(Declaration(1)))
            using (SynthRecord record = Record(1))
            {
                Assert.Equal(PredicateTier.Payload, predicate.Tier);
                Assert.True(predicate.Test(record));
                Assert.Equal(0, payloadReads);
            }
        }

        [Fact]
        public void OrEvaluatesHeaderPredicatesBeforePayloadPredicatesRegardlessOfConstructionOrder()
        {
            int payloadReads = 0;
            Predicate predicate = Filter.Custom((in EventRecordRef record) =>
            {
                payloadReads++;
                return false;
            }).Or(Filter.EventIdIs(1));

            using (EventSchema.Use(Declaration(1)))
            using (SynthRecord record = Record(1))
            {
                Assert.True(predicate.Test(record));
                Assert.Equal(0, payloadReads);
            }
        }

        [Fact]
        public void NotInvertsTheInnerPredicateAndKeepsItsTier()
        {
            Predicate predicate = Filter.EventIdIs(2).Not();

            using (EventSchema.Use(Declaration(1)))
            using (SynthRecord record = Record(1))
            {
                Assert.Equal(PredicateTier.Header, predicate.Tier);
                Assert.True(predicate.Test(record));
            }
        }

        [Fact]
        public void OperatorsAndCompatibilityMethodsComposePredicates()
        {
            using (EventSchema.Use(Declaration(1)))
            using (SynthRecord record = Record(1))
            {
                Assert.True((Filter.EventIdIs(1) & Filter.EventVersionIs(0)).Test(record));
                Assert.True((Filter.EventIdIs(2) | Filter.EventVersionIs(0)).Test(record));
                Assert.True((Filter.EventIdIs(1) && Filter.EventVersionIs(0)).Test(record));
                Assert.True((Filter.EventIdIs(2) || Filter.EventVersionIs(0)).Test(record));
                Assert.True((!Filter.EventIdIs(2)).Test(record));
                Assert.True(Filter.EventIdIs(1).op_LogicalAnd(Filter.EventVersionIs(0)).Test(record));
                Assert.True(Filter.EventIdIs(2).op_LogicalOr(Filter.EventVersionIs(0)).Test(record));
                Assert.True(Filter.EventIdIs(2).op_LogicalNot().Test(record));
            }
        }

        [Fact]
        public void NullOperandsAreRejectedAtCompositionTime()
        {
            Predicate predicate = Filter.AnyEvent();

            Assert.Throws<ArgumentNullException>(() => predicate.And(null));
            Assert.Throws<ArgumentNullException>(() => predicate.Or(null));
            Assert.Throws<ArgumentNullException>(() => predicate.op_LogicalAnd(null));
            Assert.Throws<ArgumentNullException>(() => predicate.op_LogicalOr(null));
            Assert.Throws<ArgumentNullException>(() => predicate & null);
            Assert.Throws<ArgumentNullException>(() => predicate | null);
            Assert.Throws<ArgumentNullException>(() => Filter.Not(null));
            Assert.Throws<ArgumentNullException>(() => Filter.Custom(null));
            Assert.Throws<ArgumentNullException>(() => predicate.Test(null));
        }

        [Fact]
        public void EventFilterBuiltFromAnOrOfIdsStillTestsEachIdInTheCallback()
        {
            var filter = new EventFilter(Filter.EventIdIs(1).Or(Filter.EventIdIs(2)));
            int seen = 0;
            filter.OnEventRef += (in EventRecordRef record) => seen++;

            using (EventSchema.Use(Declaration(1), Declaration(2), Declaration(3)))
            using (var proxy = new Proxy(filter))
            {
                using (SynthRecord one = Record(1))
                using (SynthRecord two = Record(2))
                using (SynthRecord three = Record(3))
                {
                    proxy.PushEvent(one);
                    proxy.PushEvent(two);
                    proxy.PushEvent(three);
                }
            }

            Assert.Equal(2, seen);
        }

        private static EventSchema Declaration(ushort id)
        {
            return EventSchema
                .Create("Filtering-Predicate-Composition-Provider", ProviderId, id, version: 0)
                .Named("Event" + id)
                .UInt32("Value");
        }

        private static SynthRecord Record(ushort id)
        {
            using (var builder = new RecordBuilder(ProviderId, id, version: 0))
            {
                builder.AddValue("Value", 1u);
                return builder.Pack();
            }
        }
    }
}
