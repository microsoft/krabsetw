using System;
using System.Net;
using Microsoft.O365.Security.ETW.Testing;
using Xunit;

namespace Microsoft.O365.Security.ETW.Tests
{
    /// <summary>
    /// Covers every cause <c>EventRecordRef.DescribeUnreadable</c> reports.
    /// </summary>
    /// <remarks>
    /// The message is the whole product of the helper: every throwing Get accessor routes
    /// through it, and the only thing it changes is where an investigation starts. A branch
    /// that reports the wrong cause still throws, still passes every other test, and sends the
    /// reader after a manifest mismatch that is not there -- so each cause is asserted here.
    /// </remarks>
    public class UnreadablePropertyDiagnosticsTests
    {
        private static readonly Guid ProviderId =
            Guid.Parse("3f2a17c8-9d54-4b61-8e0a-7c5d2b41f9e6");

        /// <summary>
        /// Offsets in the packed payload: EmptyLength 0, Empty 2, VarLength 2, Var 4,
        /// NotAnAddress 12, Tail 16, Extra 20, for twenty-four bytes in total. The truncations
        /// below are expressed against these, so a change to the declaration will move them.
        /// </summary>
        private const int VarOffset = 4;
        private const int TailOffset = 16;
        private const int FullPayload = 24;

        [Fact]
        public void APropertyAbsentFromTheSchemaIsReportedAsNotDeclared()
        {
            WithRecord(record =>
            {
                ParserException error = Assert.Throws<ParserException>(() => record.GetUInt32("Nope"));
                Assert.Contains("not declared in the event schema", error.Message, StringComparison.Ordinal);
            });
        }

        [Fact]
        public void APropertyBehindAnUnreadableOneIsReportedAsAStalledWalk()
        {
            // Tail does not fit, so the walk cannot get past it to work out where Extra starts.
            // Extra is not itself malformed -- nothing is known about it at all.
            WithRecord(
                record =>
                {
                    ParserException error = Assert.Throws<ParserException>(() => record.GetUInt32("Extra"));
                    Assert.Contains("the offset walk stalled before it", error.Message, StringComparison.Ordinal);
                    Assert.Contains("ends inside an earlier property", error.Message, StringComparison.Ordinal);
                },
                truncateTo: TailOffset);
        }

        [Fact]
        public void ARuntimeLengthPropertyCutShortIsReportedAsAnUnresolvableLength()
        {
            // Var is located, and the payload says it is eight bytes, but only four are left.
            // A payload-derived length has no fixed width to report, so this is as far as the
            // description can go.
            WithRecord(
                record =>
                {
                    ParserException error = Assert.Throws<ParserException>(() => record.GetBinary("Var"));
                    Assert.Contains("its length could not be resolved", error.Message, StringComparison.Ordinal);
                    Assert.Contains(FormattableString.Invariant($"offset {VarOffset}"), error.Message, StringComparison.Ordinal);
                },
                truncateTo: VarOffset + 4);
        }

        [Fact]
        public void AFixedWidthPropertyThatDoesNotFitIsReportedAsRunningPastThePayload()
        {
            // Tail starts exactly where the payload ends. The offset resolves, but the four
            // bytes it declares are not there.
            //
            // SizeOf refuses a length that would overrun the payload rather than returning
            // one, so without FixedSizeOf this reads as "length could not be resolved" -- a
            // decoding problem -- when the event is simply shorter than the schema says.
            WithRecord(
                record =>
                {
                    ParserException error = Assert.Throws<ParserException>(() => record.GetUInt32("Tail"));
                    Assert.Contains(
                        FormattableString.Invariant($"length 4, which runs past the {TailOffset}-byte payload"),
                        error.Message,
                        StringComparison.Ordinal);
                },
                truncateTo: TailOffset);
        }

        [Fact]
        public void AZeroLengthPropertyIsReportedAsCarryingNothingToDecode()
        {
            // The TCPIP 1422 shape: declared, present, and empty. Distinct from absent.
            WithRecord(record =>
            {
                ParserException error = Assert.Throws<ParserException>(() => record.GetIPAddress("Empty"));
                Assert.Contains("carries a zero-length value for it", error.Message, StringComparison.Ordinal);
                Assert.DoesNotContain("not declared", error.Message, StringComparison.Ordinal);
            });
        }

        [Fact]
        public void APresentPropertyTheTypeRefusesIsReportedAsRejectedByTheType()
        {
            // Four readable bytes at a known offset. Nothing is wrong with the event; the
            // address accessor refuses it because the schema never marked it as an address.
            WithRecord(record =>
            {
                ParserException error = Assert.Throws<ParserException>(() => record.GetIPAddress("NotAnAddress"));
                Assert.Contains("present as 4 bytes at offset", error.Message, StringComparison.Ordinal);
                Assert.Contains("the requested type rejected the value", error.Message, StringComparison.Ordinal);
            });
        }

        [Fact]
        public void EveryCauseReportsADistinctMessage()
        {
            // The helper exists to separate these. If two collapse onto one wording the
            // individual assertions above still pass while the diagnostic stops working.
            string notDeclared = null;
            string zeroLength = null;
            string rejected = null;
            string stalled = null;
            string unresolvable = null;
            string pastPayload = null;

            WithRecord(record =>
            {
                notDeclared = Message(() => record.GetUInt32("Nope"));
                zeroLength = Message(() => record.GetIPAddress("Empty"));
                rejected = Message(() => record.GetIPAddress("NotAnAddress"));
            });

            WithRecord(
                record =>
                {
                    stalled = Message(() => record.GetUInt32("Extra"));
                    pastPayload = Message(() => record.GetUInt32("Tail"));
                },
                truncateTo: TailOffset);

            WithRecord(
                record => unresolvable = Message(() => record.GetBinary("Var")),
                truncateTo: VarOffset + 4);

            string[] all = { notDeclared, zeroLength, rejected, stalled, unresolvable, pastPayload };

            Assert.All(all, m => Assert.False(string.IsNullOrWhiteSpace(m)));
            Assert.Equal(all.Length, new System.Collections.Generic.HashSet<string>(all, StringComparer.Ordinal).Count);
        }

        [Fact]
        public void APropertyReadWithoutAResolvableSchemaIsReportedAsHavingNoSchema()
        {
            // OnMetadata fires before anything resolves a schema and receives the same adapter
            // the event handlers get, so a consumer that reaches for a property there is reading
            // an event nothing has decoded. The record also outlives its declaration here, which
            // is what a provider whose manifest is not installed looks like.
            SynthRecord record;

            using (EventSchema.Use(Schema()))
            using (var builder = new RecordBuilder(ProviderId, id: 21, version: 0))
            {
                AddPayload(builder);
                record = builder.Pack();
            }

            var provider = new Provider(ProviderId);
            ParserException error = null;
            int seen = 0;

            provider.OnMetadata += metadata =>
            {
                seen++;
                try
                {
                    ((IEventRecord)metadata).GetUInt32("Tail");
                }
                catch (ParserException ex)
                {
                    error = ex;
                }
            };

            using (record)
            using (var trace = new UserTrace())
            {
                using var proxy = new Proxy(trace);
                trace.Enable(provider);
                proxy.PushEvent(record);
            }

            Assert.Equal(1, seen);
            Assert.NotNull(error);
            Assert.Contains("no schema could be resolved for this event", error.Message, StringComparison.Ordinal);
        }

        private static string Message(Action read)
        {
            return Assert.Throws<ParserException>(read).Message;
        }

        private static EventSchema Schema()
        {
            return EventSchema
                .Create("Contoso-Diagnostics-Provider", ProviderId, id: 21, version: 0)
                .Named("DiagnosticsEvent")
                .UInt16("EmptyLength")
                .Binary("Empty", lengthFrom: "EmptyLength")
                .UInt16("VarLength")
                .Binary("Var", lengthFrom: "VarLength")
                .Binary("NotAnAddress", length: 4)
                .UInt32("Tail")
                .UInt32("Extra");
        }

        private static void AddPayload(RecordBuilder builder)
        {
            builder.AddValue("EmptyLength", (ushort)0);
            builder.AddBinary("Empty", Array.Empty<byte>());
            builder.AddValue("VarLength", (ushort)8);
            builder.AddBinary("Var", new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 });
            builder.AddBinary("NotAnAddress", new byte[] { 1, 2, 3, 4 });
            builder.AddValue("Tail", 0x11223344u);
            builder.AddValue("Extra", 0x55667788u);
        }

        private static unsafe void WithRecord(Action<IEventRecord> assertion, int? truncateTo = null)
        {
            using (EventSchema.Use(Schema()))
            using (var builder = new RecordBuilder(ProviderId, id: 21, version: 0))
            {
                AddPayload(builder);

                using (SynthRecord record = builder.Pack())
                {
                    Assert.Equal(FullPayload, record.Record->UserDataLength);

                    if (truncateTo.HasValue)
                    {
                        // What a provider emitting a shorter variant of the event looks like to
                        // the reader: the schema is unchanged, the payload simply stops early.
                        record.Record->UserDataLength = (ushort)truncateTo.Value;
                    }

                    Push(record, assertion);
                }
            }
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
                    failure = failure ?? ex;
                }
            };

            new Proxy(filter).PushEvent(record);

            if (failure != null)
            {
                throw failure;
            }

            Assert.Equal(1, seen);
        }
    }
}
