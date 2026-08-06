using System;
using Microsoft.O365.Security.ETW.Testing;
using Xunit;

namespace Microsoft.O365.Security.ETW.Tests
{
    /// <summary>
    /// Covers the span-returning members added to <see cref="IEventRecord"/> so that a
    /// consumer on the compat path can read payloads without allocating.
    /// </summary>
    /// <remarks>
    /// The interesting property is parity: each span member must return exactly what its
    /// allocating sibling returns, so a caller can migrate one call site at a time.
    ///
    /// <see cref="RecordBuilder"/> lays the payload out from the provider's registered TDH
    /// schema, so these fixtures use real, in-box providers -- the same ones the parity suite
    /// uses. PowerShell supplies UNICODESTRING properties, WinINet ANSISTRING and a UINT32.
    /// </remarks>
    public class SpanAccessorTests
    {
        private static readonly Guid PowerShellProviderId = Guid.Parse("a0c1853b-5c40-4b15-8766-3cf1c58f985a");
        private static readonly Guid WinINetProviderId = Guid.Parse("43D1A55C-76D6-4F7E-995C-64C711E5CAFE");

        [Fact]
        public void UnicodeStringSpanMatchesTheAllocatingOverload()
        {
            WithPowerShellRecord(
                @"C:\Windows\System32\cmd.exe",
                record =>
                {
                    Assert.True(record.TryGetUnicodeString("Payload", out string expected));

                    Assert.True(record.TryGetUnicodeString("Payload".AsSpan(), out ReadOnlySpan<char> actual));
                    Assert.True(actual.SequenceEqual(expected.AsSpan()));
                    Assert.True(record.GetUnicodeString("Payload".AsSpan()).SequenceEqual(expected.AsSpan()));
                });
        }

        [Fact]
        public void UnicodeStringSpanReportsAbsentProperties()
        {
            WithPowerShellRecord(
                "value",
                record =>
                {
                    Assert.False(record.TryGetUnicodeString("Missing".AsSpan(), out ReadOnlySpan<char> value));
                    Assert.True(value.IsEmpty);
                    Assert.Throws<ParserException>(() => record.GetUnicodeString("Missing".AsSpan()).Length);
                });
        }

        [Fact]
        public void CountedStringSpanMatchesTheAllocatingOverload()
        {
            // A counted string is a little-endian UINT16 byte count followed by that many
            // bytes of character data. The interpretation is forced, not derived from the
            // in-type, so a plain UNICODESTRING property carries one here.
            WithPowerShellRecord(
                "\u0008abcd",
                record =>
                {
                    Assert.True(record.TryGetCountedString("Payload", out string expected));
                    Assert.Equal("abcd", expected);

                    Assert.True(record.TryGetCountedString("Payload".AsSpan(), out ReadOnlySpan<char> actual));
                    Assert.True(actual.SequenceEqual(expected.AsSpan()));
                    Assert.True(record.GetCountedString("Payload".AsSpan()).SequenceEqual(expected.AsSpan()));
                });
        }

        [Fact]
        public void CountedStringSpanReportsAbsentProperties()
        {
            WithPowerShellRecord(
                "\u0008abcd",
                record =>
                {
                    Assert.False(record.TryGetCountedString("Missing".AsSpan(), out ReadOnlySpan<char> value));
                    Assert.True(value.IsEmpty);
                    Assert.Throws<ParserException>(() => record.GetCountedString("Missing".AsSpan()).Length);
                });
        }

        [Fact]
        public void AnsiStringBytesMatchTheDecodedOverload()
        {
            WithWinINetRecord(record =>
            {
                Assert.True(record.TryGetAnsiString("Verb", out string expected));
                Assert.Equal("GET", expected);

                Assert.True(record.TryGetAnsiStringBytes("Verb".AsSpan(), out ReadOnlySpan<byte> actual));
                Assert.Equal(expected.Length, actual.Length);

                // ASCII is a fixed point of every ANSI code page, so the raw bytes and the
                // decoded characters agree one for one here.
                for (int i = 0; i < actual.Length; i++)
                {
                    Assert.Equal((byte)expected[i], actual[i]);
                }

                Assert.False(record.TryGetAnsiStringBytes("Missing".AsSpan(), out ReadOnlySpan<byte> missing));
                Assert.True(missing.IsEmpty);
            });
        }

        [Fact]
        public void BinarySpanMatchesTheAllocatingOverload()
        {
            WithWinINetRecord(record =>
            {
                Assert.True(record.TryGetBinary("Status", out byte[] expected));

                Assert.True(record.TryGetBinary("Status".AsSpan(), out ReadOnlySpan<byte> actual));
                Assert.True(actual.SequenceEqual(expected));

                Assert.False(record.TryGetBinary("Missing".AsSpan(), out ReadOnlySpan<byte> missing));
                Assert.True(missing.IsEmpty);
            });
        }

        [Fact]
        public void SpanAccessorsDoNotAllocate()
        {
            WithWinINetRecord(record =>
            {
                long consumed = 0;

                // The first pass warms the schema and property caches and jits the
                // accessors; only the second is measured.
                for (int pass = 0; pass < 2; pass++)
                {
                    long before = GC.GetAllocatedBytesForCurrentThread();

                    for (int i = 0; i < 64; i++)
                    {
                        consumed += record.GetCountedString("URL".AsSpan()).Length;
                        record.TryGetAnsiStringBytes("Verb".AsSpan(), out ReadOnlySpan<byte> verb);
                        consumed += verb.Length;
                        record.TryGetAnsiStringBytes("URL".AsSpan(), out ReadOnlySpan<byte> url);
                        consumed += url.Length;
                        record.TryGetBinary("Status".AsSpan(), out ReadOnlySpan<byte> status);
                        consumed += status.Length;
                    }

                    if (pass == 1)
                    {
                        Assert.Equal(0, GC.GetAllocatedBytesForCurrentThread() - before);
                    }
                }

                Assert.True(consumed > 0);
            });
        }

        private static void WithPowerShellRecord(string payload, Action<IEventRecord> assert)
        {
            using (var builder = new RecordBuilder(PowerShellProviderId, 7937, 1))
            {
                builder.AddUnicodeString("UserData", "user");
                builder.AddUnicodeString("ContextInfo", "context");
                builder.AddUnicodeString("Payload", payload);

                Push(builder.Pack(), assert);
            }
        }

        private static void WithWinINetRecord(Action<IEventRecord> assert)
        {
            using (var builder = new RecordBuilder(WinINetProviderId, 1057, 0))
            {
                builder.AddAnsiString("URL", "http://example.invalid/index.html");
                builder.AddAnsiString("Verb", "GET");
                builder.AddValue("Status", 200u);

                // Later revisions of this event carry header properties this test does not
                // need; pack tolerantly rather than pin the fixture to one Windows build.
                Push(builder.PackIncomplete(), assert);
            }
        }

        /// <summary>
        /// Pushes a synthetic record through an <see cref="EventFilter"/> so the callback sees
        /// the very same record instance a live trace would hand it.
        /// </summary>
        private static void Push(SynthRecord record, Action<IEventRecord> assert)
        {
            var filter = new EventFilter(Filter.AnyEvent());
            Exception failure = null;
            int seen = 0;

            filter.OnEvent += evt =>
            {
                seen++;
                try
                {
                    assert(evt);
                }
                catch (Exception ex)
                {
                    failure = ex;
                }
            };

            using (var proxy = new Proxy(filter))
            using (record)
            {
                proxy.PushEvent(record);
            }

            Assert.Equal(1, seen);
            if (failure != null)
            {
                throw new Xunit.Sdk.XunitException(failure.ToString());
            }
        }
    }
}
