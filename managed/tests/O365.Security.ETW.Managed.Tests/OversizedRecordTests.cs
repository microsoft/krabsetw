using System;
using Microsoft.O365.Security.ETW.Testing;
using Xunit;

namespace Microsoft.O365.Security.ETW.Tests
{
    /// <summary>
    /// Covers a synthetic record whose payload is too large for EVENT_RECORD to describe.
    /// </summary>
    /// <remarks>
    /// UserDataLength is a USHORT, so a payload of 64 KiB or more cannot be expressed. Left
    /// to the cast, the length wraps and the record decodes as a much shorter one -- every
    /// property beyond the wrapped length reads as absent, for no reason the test author can
    /// see. Pack refuses to build it instead.
    /// </remarks>
    public class OversizedRecordTests
    {
        private static readonly Guid LargeProviderId =
            Guid.Parse("b2d9c4e1-58a7-4f30-9c62-3ae5d1f80b4a");

        private static EventSchema Declaration()
        {
            return EventSchema
                .Create("Contoso-Large-Provider", LargeProviderId, id: 12, version: 0)
                .Named("BlobLogged")
                .UnicodeString("Text")
                .UInt32("Status");
        }

        [Fact]
        public void APayloadTooLargeForUserDataLengthIsRejected()
        {
            using (EventSchema.Use(Declaration()))
            using (var builder = new RecordBuilder(LargeProviderId, id: 12, version: 0))
            {
                builder.AddUnicodeString("Text", new string('a', 40000));
                builder.AddValue("Status", 1u);

                var error = Assert.Throws<ArgumentException>(() => builder.Pack());
                Assert.Contains("65535", error.Message);
            }
        }

        /// <summary>
        /// The largest payload that still fits has to keep working: an off-by-one in the
        /// guard would be as unhelpful as the wrap it replaces.
        /// </summary>
        [Fact]
        public void ThePayloadThatExactlyFitsIsAccepted()
        {
            // Status (4) plus the string's NUL terminator (2) leaves 65529 bytes for the text.
            using (EventSchema.Use(Declaration()))
            using (var builder = new RecordBuilder(LargeProviderId, id: 12, version: 0))
            {
                var text = new string('a', (ushort.MaxValue - 4 - 2) / 2);
                builder.AddUnicodeString("Text", text);
                builder.AddValue("Status", 0x0BADF00Du);

                var filter = new EventFilter(Filter.AnyEvent());
                Exception failure = null;
                int seen = 0;

                filter.OnEventRef += (in EventRecordRef record) =>
                {
                    try
                    {
                        Assert.True(record.TryGetUInt32("Status".AsSpan(), out uint status));
                        Assert.Equal(0x0BADF00Du, status);
                        seen++;
                    }
                    catch (Exception ex)
                    {
                        failure = failure ?? ex;
                    }
                };

                new Proxy(filter).PushEvent(builder.Pack());

                if (failure != null)
                {
                    throw failure;
                }

                Assert.Equal(1, seen);
            }
        }
    }
}
