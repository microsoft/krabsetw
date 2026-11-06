using System;
using System.Text;
using Microsoft.O365.Security.ETW;
using Microsoft.O365.Security.ETW.Interop;
using Microsoft.O365.Security.ETW.Testing;
using Xunit;

namespace Microsoft.O365.Security.ETW.Tests
{
    /// <summary>
    /// An 8-bit string property carries the ANSI code page only when its out-type says so.
    /// <c>win:UTF8</c> and <c>win:JSON</c> are UTF-8, and decoding them with the ANSI code
    /// page corrupts every character above U+007F.
    /// </summary>
    public class AnsiOutTypeTests
    {
        private static readonly Guid ProviderId = Guid.Parse("2f7c1e5a-9c44-4f6b-9c1a-6d3f0e5b8a21");

        /// <summary>
        /// Characters that encode differently in UTF-8 and in any single byte code page.
        /// </summary>
        private const string Text = "caf\u00e9 \u00fcber";

        private delegate void RefAssert(in EventRecordRef record);

        [Fact]
        public void Utf8PropertiesAreEncodedAndDecodedAsUtf8()
        {
            var schema = EventSchema
                .Create("Contoso-Utf8-Provider", ProviderId, id: 1, version: 0)
                .Utf8String("Text");

            using (EventSchema.Use(schema))
            {
                WithRecord(
                    schema,
                    (in EventRecordRef record) =>
                    {
                        Assert.True(record.TryGetAnsiStringBytes("Text".AsSpan(), out ReadOnlySpan<byte> bytes));
                        Assert.Equal(Encoding.UTF8.GetBytes(Text), bytes.ToArray());
                    },
                    record => Assert.Equal(Text, record.GetAnsiString("Text")));
            }
        }

        [Fact]
        public void JsonPropertiesAreEncodedAndDecodedAsUtf8()
        {
            var schema = EventSchema
                .Create("Contoso-Json-Provider", ProviderId, id: 2, version: 0)
                .JsonString("Document");

            using (EventSchema.Use(schema))
            {
                using (var builder = new RecordBuilder(ProviderId, id: 2, version: 0))
                {
                    builder.AddAnsiString("Document", "{\"name\":\"" + Text + "\"}");

                    Push(
                        builder.Pack(),
                        null,
                        record => Assert.Equal("{\"name\":\"" + Text + "\"}", record.GetAnsiString("Document")));
                }
            }
        }

        [Fact]
        public void PlainAnsiPropertiesStillUseTheAnsiCodePage()
        {
            var schema = EventSchema
                .Create("Contoso-Ansi-Provider", ProviderId, id: 3, version: 0)
                .AnsiString("Text");

            using (EventSchema.Use(schema))
            {
                using (var builder = new RecordBuilder(ProviderId, id: 3, version: 0))
                {
                    builder.AddAnsiString("Text", Text);

                    Push(
                        builder.Pack(),
                        (in EventRecordRef record) =>
                        {
                            Assert.True(record.TryGetAnsiStringBytes("Text".AsSpan(), out ReadOnlySpan<byte> bytes));
                            Assert.Equal(AnsiEncoding.Current.GetBytes(Text), bytes.ToArray());
                        },
                        null);
                }
            }
        }

        [Fact]
        public void PredicatesCompareUtf8PropertiesAsUtf8()
        {
            var schema = EventSchema
                .Create("Contoso-Utf8-Provider", ProviderId, id: 4, version: 0)
                .Utf8String("Text");

            using (EventSchema.Use(schema))
            {
                using (var builder = new RecordBuilder(ProviderId, id: 4, version: 0))
                {
                    builder.AddAnsiString("Text", Text);

                    var filter = new EventFilter(AnsiString.Is("Text", Text));
                    int seen = 0;
                    filter.OnEventRef += (in EventRecordRef record) => seen++;

                    using (var proxy = new Proxy(filter))
                    using (SynthRecord record = builder.Pack())
                    {
                        proxy.PushEvent(record);
                    }

                    Assert.Equal(1, seen);
                }
            }
        }

        private static void WithRecord(EventSchema schema, RefAssert refAssert, Action<IEventRecord> compatAssert)
        {
            using (var builder = new RecordBuilder(ProviderId, id: 1, version: 0))
            {
                builder.AddAnsiString("Text", Text);
                Push(builder.Pack(), refAssert, compatAssert);
            }
        }

        private static void Push(SynthRecord record, RefAssert refAssert, Action<IEventRecord> compatAssert)
        {
            var filter = new EventFilter(Filter.AnyEvent());
            Exception failure = null;
            int seen = 0;

            if (refAssert != null)
            {
                filter.OnEventRef += (in EventRecordRef evt) =>
                {
                    seen++;
                    try
                    {
                        refAssert(evt);
                    }
                    catch (Exception ex)
                    {
                        failure ??= ex;
                    }
                };
            }

            if (compatAssert != null)
            {
                filter.OnEvent += evt =>
                {
                    seen++;
                    try
                    {
                        compatAssert(evt);
                    }
                    catch (Exception ex)
                    {
                        failure ??= ex;
                    }
                };
            }

            using (var proxy = new Proxy(filter))
            using (record)
            {
                proxy.PushEvent(record);
            }

            Assert.True(seen > 0);

            if (failure != null)
            {
                throw failure;
            }
        }
    }
}
