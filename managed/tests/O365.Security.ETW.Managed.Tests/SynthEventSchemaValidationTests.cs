using System;
using Microsoft.O365.Security.ETW.Testing;
using Xunit;

namespace Microsoft.O365.Security.ETW.Tests
{
    /// <summary>
    /// Covers validation performed while declaring synthetic schemas.
    /// </summary>
    /// <remarks>
    /// A bad declaration describes an event shape no provider can emit. The declaration API
    /// rejects those shapes before a record is packed so tests fail at the fixture boundary.
    /// </remarks>
    public class SynthEventSchemaValidationTests
    {
        private static readonly Guid ProviderId = Guid.Parse("cddfa0a6-7ca0-4bde-9c19-83c53e764881");

        [Theory]
        [InlineData(-1, 0, "id")]
        [InlineData(65536, 0, "id")]
        [InlineData(1, -1, "version")]
        [InlineData(1, 256, "version")]
        public void CreateRejectsIdsAndVersionsOutsideTheEtwHeaderRange(int id, int version, string parameter)
        {
            var error = Assert.Throws<ArgumentOutOfRangeException>(() => EventSchema.Create("Contoso", ProviderId, id, version));
            Assert.Equal(parameter, error.ParamName);
        }

        [Fact]
        public void PropertiesRequireNonEmptyUniqueNames()
        {
            EventSchema schema = EventSchema.Create("Contoso", ProviderId, id: 1, version: 0);

            var empty = Assert.Throws<ArgumentException>(() => schema.UInt32(string.Empty));
            Assert.Equal("name", empty.ParamName);
            Assert.Contains("name", empty.Message);

            schema.UInt32("Value");
            var duplicate = Assert.Throws<ArgumentException>(() => schema.UInt16("Value"));
            Assert.Equal("name", duplicate.ParamName);
            Assert.Contains("Value", duplicate.Message);
        }

        [Fact]
        public void SizedPropertiesMustReferenceAnEarlierProperty()
        {
            EventSchema schema = EventSchema.Create("Contoso", ProviderId, id: 2, version: 0);

            var error = Assert.Throws<ArgumentException>(() => schema.UnicodeString("Text", lengthFrom: "Length"));
            Assert.Equal("lengthFrom", error.ParamName);
            Assert.Contains("Text", error.Message);
            Assert.Contains("Length", error.Message);
        }

        [Theory]
        [InlineData(-1)]
        [InlineData(65536)]
        public void BinaryLengthMustFitInTheEtwSchemaField(int length)
        {
            EventSchema schema = EventSchema.Create("Contoso", ProviderId, id: 3, version: 0);

            var error = Assert.Throws<ArgumentOutOfRangeException>(() => schema.Binary("Blob", length));
            Assert.Equal("length", error.ParamName);
        }

        [Fact]
        public void UseRejectsNullSchemaArraysAndNullDeclarations()
        {
            var nullArray = Assert.Throws<ArgumentNullException>(() => EventSchema.Use(null));
            Assert.Equal("schemas", nullArray.ParamName);

            var nullElement = Assert.Throws<ArgumentException>(() => EventSchema.Use(EventSchema.Create("Contoso", ProviderId, id: 4), null));
            Assert.Equal("schemas", nullElement.ParamName);
            Assert.Contains("null", nullElement.Message, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void InnerDeclarationsOverrideOuterDeclarationsAndDisposalRestoresTheOuterScope()
        {
            EventSchema outer = EventSchema
                .Create("Contoso-Outer", ProviderId, id: 5, version: 0)
                .Named("Outer")
                .UInt32("Value");
            EventSchema inner = EventSchema
                .Create("Contoso-Inner", ProviderId, id: 5, version: 0)
                .Named("Inner")
                .UInt32("Value");

            using (EventSchema.Use(outer))
            {
                Assert.Equal("Outer", ReadName(id: 5));

                using (EventSchema.Use(inner))
                {
                    Assert.Equal("Inner", ReadName(id: 5));
                }

                Assert.Equal("Outer", ReadName(id: 5));
            }
        }

        private static string ReadName(int id)
        {
            using (var builder = new RecordBuilder(ProviderId, id, version: 0))
            {
                builder.AddValue("Value", 1u);

                var filter = new EventFilter(Filter.AnyEvent());
                string name = null;
                Exception failure = null;
                int seen = 0;

                filter.OnEventRef += (in Microsoft.O365.Security.ETW.EventRecordRef record) =>
                {
                    seen++;
                    try
                    {
                        name = record.Name.ToString();
                    }
                    catch (Exception ex)
                    {
                        failure ??= ex;
                    }
                };

                using (var proxy = new Proxy(filter))
                using (SynthRecord record = builder.Pack())
                {
                    proxy.PushEvent(record);
                }

                Assert.Equal(1, seen);
                if (failure != null)
                {
                    throw failure;
                }

                return name;
            }
        }
    }
}
