using System;
using Microsoft.O365.Security.ETW.Testing;
using Xunit;

namespace Microsoft.O365.Security.ETW.Tests
{
    /// <summary>
    /// Covers the padding an unfilled property contributes to a synthetic record.
    /// </summary>
    /// <remarks>
    /// A test that leaves a property unfilled is saying "I do not care about this one", not
    /// "leave a hole in the record". The padding therefore has to be exactly as wide as the
    /// reader will believe the property is, or every later property moves.
    /// </remarks>
    public class UnfilledPropertyTests
    {
        private static readonly Guid SidProviderId =
            Guid.Parse("6c1f4a90-2d33-49b7-95a4-1c8f0b6e77d2");

        private static EventSchema Declaration()
        {
            return EventSchema
                .Create("Contoso-Sid-Provider", SidProviderId, id: 11, version: 0)
                .Named("AccessChecked")
                .Sid("Owner")
                .UInt32("Status");
        }

        /// <summary>
        /// A zeroed SID is eight bytes on any machine: the reader derives the size from the
        /// SubAuthorityCount byte, and a zeroed SID declares no sub-authorities, leaving the
        /// fixed Revision(1) SubAuthorityCount(1) IdentifierAuthority(6) header. Padding by
        /// the pointer width instead leaves four bytes on a 32-bit record, so the reader
        /// swallows the first half of the next property.
        /// </summary>
        [Theory]
        [InlineData(4)]
        [InlineData(8)]
        public void AnUnfilledSidPadsTheWidthTheReaderWillConsume(int pointerSize)
        {
            using (EventSchema.Use(Declaration()))
            {
                SynthRecord record;

                using (var builder = new RecordBuilder(SidProviderId, id: 11, version: 0))
                {
                    if (pointerSize == 4)
                    {
                        builder.Header.Flags = (ushort)EventHeaderFlags.HEADER_32_BIT;
                    }

                    builder.AddValue("Status", 0x11223344u);
                    record = builder.PackIncomplete();
                }

                var filter = new EventFilter(Filter.AnyEvent());
                Exception failure = null;
                int seen = 0;

                filter.OnEventRef += (in EventRecordRef read) =>
                {
                    try
                    {
                        Assert.True(read.TryGetUInt32("Status".AsSpan(), out uint status));
                        Assert.Equal(0x11223344u, status);
                        seen++;
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
}
