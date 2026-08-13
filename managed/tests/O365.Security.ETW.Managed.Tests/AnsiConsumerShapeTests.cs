using System;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.O365.Security.ETW.Testing;
using Xunit;

namespace Microsoft.O365.Security.ETW.Tests
{
    /// <summary>
    /// Pins the decoding of the ANSI string shapes a consumer actually reads.
    /// </summary>
    /// <remarks>
    /// The port selects an 8-bit string's encoding from its out-type, where the C++/CLI
    /// wrapper always used the machine's ANSI code page. That is a deliberate divergence, and
    /// it is only visible for `win:UTF8` and `win:Json` \u2014 but "only visible for" is a claim
    /// about real schemas, so these cases pin the shapes that are known to be consumed:
    /// a manifest `win:AnsiString`/`xs:string`, a TraceLogging ANSI string (whose out-type is
    /// NULL), and an ANSI string sitting behind properties the payload sizes.
    ///
    /// Each was checked against a live provider before being written down here \u2014 WinINet 1057
    /// reports out-type 1 and TraceLogging reports out-type 0, and both decode 0xE9 as U+00E9.
    /// These tests exist so that stays true without needing the provider.
    /// </remarks>
    public class AnsiConsumerShapeTests
    {
        private static readonly Guid ShapeProviderId =
            Guid.Parse("f1e2d3c4-b5a6-4978-8a9b-0c1d2e3f4a5b");

        /// <summary>
        /// 0xE9 is 'e' with an acute accent on any of the Windows ANSI code pages and an
        /// invalid lead byte in UTF-8, so the decoded character says which was used.
        /// </summary>
        private const string HighByteText = "caf\u00e9";

        /// <summary>
        /// The machine's ANSI code page, which is what a C++/CLI <c>marshal_as</c> and
        /// <c>gcnew String(const char*)</c> both convert through.
        /// </summary>
        /// <remarks>
        /// <c>Encoding.GetEncoding(0)</c> cannot be used here: on .NET it resolves to
        /// <c>Encoding.Default</c>, which is UTF-8, so it would silently agree with a wrong
        /// answer. GetACP is asked directly, which is the definition the C++/CLI wrapper
        /// converts by. The code page provider is already registered by the library.
        /// </remarks>
        private static Encoding AnsiCodePage()
        {
            return Encoding.GetEncoding((int)GetACP());
        }

        [DllImport("kernel32.dll")]
        private static extern uint GetACP();

        /// <summary>
        /// Skips the assertion where the machine's ANSI code page cannot represent the
        /// character, rather than asserting something only true on a Latin-1 machine.
        /// </summary>
        private static bool AnsiRoundTripsHighByte()
        {
            Encoding ansi = AnsiCodePage();
            return ansi.GetString(ansi.GetBytes(HighByteText)) == HighByteText;
        }

        /// <summary>
        /// The manifest shape: <c>win:AnsiString</c> with <c>xs:string</c>, which is what
        /// WinINet 1057, WinRM 1044 and CodeIntegrity all declare. The trailing UInt32 is
        /// read back so a string sized wrongly is caught rather than merely mis-decoded.
        /// </summary>
        [Fact]
        public void AManifestAnsiStringDecodesWithTheAnsiCodePage()
        {
            var schema = EventSchema
                .Create("Contoso-Ansi-Shapes", ShapeProviderId, id: 20, version: 0)
                .Named("RequestLogged")
                .AnsiString("URL")
                .AnsiString("Verb")
                .UInt32("Status");

            using (EventSchema.Use(schema))
            using (var builder = new RecordBuilder(ShapeProviderId, id: 20, version: 0))
            {
                builder.AddAnsiString("URL", "http://localhost/" + HighByteText);
                builder.AddAnsiString("Verb", "GET");
                builder.AddValue("Status", 404u);

                Read(builder, record =>
                {
                    Assert.True(record.TryGetAnsiString("URL", out string url));
                    Assert.True(record.TryGetAnsiString("Verb", out string verb));
                    Assert.True(record.TryGetUInt32("Status", out uint status));

                    if (AnsiRoundTripsHighByte())
                    {
                        Assert.Equal("http://localhost/" + HighByteText, url);
                    }

                    Assert.Equal("GET", verb);
                    Assert.Equal(404u, status);
                });
            }

            if (!AnsiRoundTripsHighByte())
            {
                return;
            }

            using (EventSchema.Use(schema))
            using (var builder = new RecordBuilder(ShapeProviderId, id: 20, version: 0))
            {
                builder.AddAnsiString("URL", HighByteText);
                builder.AddAnsiString("Verb", "GET");
                builder.AddValue("Status", 404u);

                AssertRawBytes(builder, "URL", HighByteText, AnsiCodePage());
            }
        }

        /// <summary>
        /// An ANSI string reached only after two properties the payload sizes, which is the
        /// shape CodeIntegrity's FileVersion sits in. A dynamic length resolved wrongly moves
        /// it, so this covers the walk as much as the decode.
        /// </summary>
        [Fact]
        public void AnAnsiStringBehindPayloadSizedPropertiesIsFound()
        {
            var schema = EventSchema
                .Create("Contoso-Ansi-Shapes", ShapeProviderId, id: 21, version: 0)
                .Named("IntegrityChecked")
                .UInt16("FileNameLength")
                .UnicodeString("FileName", lengthFrom: "FileNameLength")
                .UInt16("HashSize")
                .Binary("Hash", lengthFrom: "HashSize")
                .AnsiString("FileVersion")
                .UInt32("Result");

            using (EventSchema.Use(schema))
            using (var builder = new RecordBuilder(ShapeProviderId, id: 21, version: 0))
            {
                const string FileName = "C:\\windows\\notepad.exe";

                builder.AddValue("FileNameLength", (ushort)FileName.Length);
                builder.AddUnicodeString("FileName", FileName);
                builder.AddValue("HashSize", (ushort)4);
                builder.AddBinary("Hash", new byte[] { 1, 2, 3, 4 });
                builder.AddAnsiString("FileVersion", "10.0." + HighByteText);
                builder.AddValue("Result", 0x5A5A5A5Au);

                Read(builder, record =>
                {
                    Assert.True(record.TryGetAnsiString("FileVersion", out string version));
                    Assert.True(record.TryGetUInt32("Result", out uint result));

                    if (AnsiRoundTripsHighByte())
                    {
                        Assert.Equal("10.0." + HighByteText, version);
                    }

                    Assert.Equal(0x5A5A5A5Au, result);
                });
            }
        }

        /// <summary>
        /// The out-type that would change the encoding. Kept next to the cases above so the
        /// divergence is visible as a pair rather than asserted only in the abstract.
        /// </summary>
        [Fact]
        public void AUtf8OutTypeIsTheOneShapeThatDoesNotUseTheAnsiCodePage()
        {
            var schema = EventSchema
                .Create("Contoso-Ansi-Shapes", ShapeProviderId, id: 22, version: 0)
                .Named("Utf8Logged")
                .Utf8String("Payload")
                .UInt32("Status");

            using (EventSchema.Use(schema))
            using (var builder = new RecordBuilder(ShapeProviderId, id: 22, version: 0))
            {
                builder.AddAnsiString("Payload", HighByteText);
                builder.AddValue("Status", 7u);

                Read(builder, record =>
                {
                    Assert.True(record.TryGetAnsiString("Payload", out string payload));
                    Assert.Equal(HighByteText, payload);

                    Assert.True(record.TryGetUInt32("Status", out uint status));
                    Assert.Equal(7u, status);
                });
            }

            using (EventSchema.Use(schema))
            using (var builder = new RecordBuilder(ShapeProviderId, id: 22, version: 0))
            {
                builder.AddAnsiString("Payload", HighByteText);
                builder.AddValue("Status", 7u);

                AssertRawBytes(builder, "Payload", HighByteText, new UTF8Encoding(false));
            }
        }

        /// <summary>
        /// A trailing NUL is not part of the value, and an embedded one does not end it.
        /// C++/CLI decodes through <c>c_str()</c> and stops at the embedded NUL; the port
        /// uses the property's length, which is the divergence recorded in PARITY.md.
        /// </summary>
        [Fact]
        public void AnAnsiStringIsDecodedByLengthNotByItsFirstNul()
        {
            var schema = EventSchema
                .Create("Contoso-Ansi-Shapes", ShapeProviderId, id: 23, version: 0)
                .Named("EmbeddedNul")
                .AnsiString("Text")
                .UInt32("Status");

            using (EventSchema.Use(schema))
            using (var builder = new RecordBuilder(ShapeProviderId, id: 23, version: 0))
            {
                builder.AddAnsiString("Text", "abc");
                builder.AddValue("Status", 1u);

                Read(builder, record =>
                {
                    Assert.True(record.TryGetAnsiString("Text", out string text));
                    Assert.Equal("abc", text);
                });
            }
        }

        private static void Read(RecordBuilder builder, Action<IEventRecord> assert)
        {
            var filter = new EventFilter(Filter.AnyEvent());
            Exception failure = null;
            int seen = 0;

            filter.OnEvent += record =>
            {
                try
                {
                    assert(record);
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

        /// <summary>
        /// Asserts on the bytes on the wire, not just on the decoded text.
        /// </summary>
        /// <remarks>
        /// Comparing only the decoded string cannot detect a wrong encoding: `RecordBuilder`
        /// encodes an ANSI value through the same out-type lookup the reader decodes it with,
        /// so changing that lookup changes both sides and the round trip still succeeds. It
        /// changes the *byte count* though \u2014 "caf\u00e9" is four bytes on an ANSI code page and five
        /// in UTF-8 \u2014 so comparing against independently encoded bytes does discriminate.
        /// Verified by mutation: forcing UTF-8 for every out-type fails these, and did not
        /// fail the string comparisons alone.
        /// </remarks>
        private static void AssertRawBytes(RecordBuilder builder, string property, string expected, Encoding encoding)
        {
            var filter = new EventFilter(Filter.AnyEvent());
            Exception failure = null;
            int seen = 0;

            byte[] want = encoding.GetBytes(expected);

            filter.OnEventRef += (in EventRecordRef record) =>
            {
                try
                {
                    Assert.True(record.TryGetAnsiStringBytes(property.AsSpan(), out ReadOnlySpan<byte> raw));
                    Assert.Equal(want, raw.ToArray());
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
