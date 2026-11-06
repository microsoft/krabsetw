using System;
using Microsoft.O365.Security.ETW.Testing;
using Xunit;

namespace Microsoft.O365.Security.ETW.Tests
{
    /// <summary>
    /// Covers binary properties whose width the schema fixes rather than the value.
    /// </summary>
    /// <remarks>
    /// The reader takes a fixed-width BINARY property's size from the schema and ignores the
    /// bytes, so supplying a value of a different length silently shifts every later property.
    /// A fixture that does that produces a record no provider could emit, and the test built
    /// on it fails for a reason that has nothing to do with the code under test -- or worse,
    /// passes while reading adjacent bytes. Pack rejects it instead.
    /// </remarks>
    public class FixedWidthBinaryTests
    {
        private static readonly Guid BinaryProviderId =
            Guid.Parse("3e6a2f18-9c47-4b6d-8f21-70d5c4a9b311");

        private static EventSchema Declaration()
        {
            return EventSchema
                .Create("Contoso-Binary-Provider", BinaryProviderId, id: 7, version: 0)
                .Named("BlobWritten")
                .Binary("Blob", length: 16)
                .UInt32("Status");
        }

        [Fact]
        public void AFixedWidthBinaryOfTheDeclaredLengthRoundTrips()
        {
            var blob = new byte[16];
            for (int i = 0; i < blob.Length; i++)
            {
                blob[i] = (byte)(i + 1);
            }

            using (EventSchema.Use(Declaration()))
            using (var builder = new RecordBuilder(BinaryProviderId, id: 7, version: 0))
            {
                builder.AddBinary("Blob", blob);
                builder.AddValue("Status", 0xAABBCCDDu);

                var filter = new EventFilter(Filter.AnyEvent());
                Exception failure = null;
                int seen = 0;

                filter.OnEventRef += (in EventRecordRef record) =>
                {
                    try
                    {
                        Assert.True(record.TryGetBinary("Blob".AsSpan(), out ReadOnlySpan<byte> read));
                        Assert.Equal(blob, read.ToArray());

                        Assert.True(record.TryGetUInt32("Status".AsSpan(), out uint status));
                        Assert.Equal(0xAABBCCDDu, status);

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

        [Theory]
        [InlineData(4)]
        [InlineData(20)]
        public void AFixedWidthBinaryOfTheWrongLengthIsRejected(int supplied)
        {
            using (EventSchema.Use(Declaration()))
            using (var builder = new RecordBuilder(BinaryProviderId, id: 7, version: 0))
            {
                builder.AddBinary("Blob", new byte[supplied]);
                builder.AddValue("Status", 1u);

                var error = Assert.Throws<ArgumentException>(() => builder.Pack());
                Assert.Contains("Blob", error.Message);
                Assert.Contains("16", error.Message);
            }
        }
    }
}
