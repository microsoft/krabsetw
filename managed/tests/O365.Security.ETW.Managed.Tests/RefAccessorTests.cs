using System;
using Microsoft.O365.Security.ETW.Testing;
using Xunit;

namespace Microsoft.O365.Security.ETW.Tests
{
    /// <summary>
    /// Covers the allocation-free accessors on <see cref="EventRecordRef"/>.
    /// </summary>
    /// <remarks>
    /// The interesting property is parity across the two surfaces: what the ref accessor
    /// views in place must equal what the allocating <see cref="IEventRecord"/> accessor
    /// materialises, so a consumer can migrate a handler and trust it still sees the same
    /// payload. Both handlers are subscribed to one filter and the ref handler runs first,
    /// so each test reads a value through the ref surface, keeps a copy, and lets the compat
    /// handler compare against its own independent read.
    ///
    /// <see cref="RecordBuilder"/> lays the payload out from the provider's registered TDH
    /// schema, so these fixtures use real, in-box providers -- the same ones the parity suite
    /// uses. PowerShell supplies UNICODESTRING properties, WinINet ANSISTRING and a UINT32.
    /// </remarks>
    public class RefAccessorTests
    {
        private static readonly Guid PowerShellProviderId = Guid.Parse("a0c1853b-5c40-4b15-8766-3cf1c58f985a");
        private static readonly Guid WinINetProviderId = Guid.Parse("43D1A55C-76D6-4F7E-995C-64C711E5CAFE");

        /// <summary>Receives a record on the allocation-free surface.</summary>
        /// <remarks>
        /// Declared here rather than reusing <see cref="EventRecordDelegate"/> only so the
        /// tests read as assertions rather than as event handlers.
        /// </remarks>
        private delegate void RefAssert(in EventRecordRef record);

        [Fact]
        public void UnicodeStringMatchesTheAllocatingSurface()
        {
            string viaRef = null;

            WithPowerShellRecord(
                @"C:\Windows\System32\cmd.exe",
                (in EventRecordRef record) =>
                {
                    Assert.True(record.TryGetUnicodeString("Payload", out ReadOnlySpan<char> value));
                    viaRef = value.ToString();

                    Assert.True(record.GetUnicodeString("Payload").SequenceEqual(value));
                },
                record =>
                {
                    Assert.Equal(record.GetUnicodeString("Payload"), viaRef);
                });
        }

        [Fact]
        public void UnicodeStringReportsAbsentProperties()
        {
            WithPowerShellRecord(
                "value",
                (in EventRecordRef record) =>
                {
                    Assert.False(record.TryGetUnicodeString("Missing", out ReadOnlySpan<char> value));
                    Assert.True(value.IsEmpty);

                    // The record cannot be captured, so the throwing case is asserted inline
                    // rather than through Assert.Throws.
                    try
                    {
                        _ = record.GetUnicodeString("Missing").Length;
                        Assert.Fail("GetUnicodeString should have thrown for an absent property.");
                    }
                    catch (ParserException)
                    {
                    }
                });
        }

        [Fact]
        public void CountedStringMatchesTheAllocatingSurface()
        {
            // A counted string is a little-endian UINT16 byte count followed by that many
            // bytes of character data. The interpretation is forced, not derived from the
            // in-type, so a plain UNICODESTRING property carries one here.
            string viaRef = null;

            WithPowerShellRecord(
                "\u0008abcd",
                (in EventRecordRef record) =>
                {
                    Assert.True(record.TryGetCountedString("Payload", out ReadOnlySpan<char> value));
                    viaRef = value.ToString();

                    Assert.True(record.GetCountedString("Payload").SequenceEqual(value));
                },
                record =>
                {
                    Assert.Equal("abcd", viaRef);
                    Assert.Equal(record.GetCountedString("Payload"), viaRef);
                });
        }

        [Fact]
        public void CountedStringReportsAbsentProperties()
        {
            WithPowerShellRecord(
                "\u0008abcd",
                (in EventRecordRef record) =>
                {
                    Assert.False(record.TryGetCountedString("Missing", out ReadOnlySpan<char> value));
                    Assert.True(value.IsEmpty);

                    try
                    {
                        _ = record.GetCountedString("Missing").Length;
                        Assert.Fail("GetCountedString should have thrown for an absent property.");
                    }
                    catch (ParserException)
                    {
                    }
                });
        }

        [Fact]
        public void AnsiStringBytesMatchTheDecodedSurface()
        {
            byte[] viaRef = null;

            WithWinINetRecord(
                (in EventRecordRef record) =>
                {
                    Assert.True(record.TryGetAnsiStringBytes("Verb", out ReadOnlySpan<byte> value));
                    viaRef = value.ToArray();

                    Assert.False(record.TryGetAnsiStringBytes("Missing", out ReadOnlySpan<byte> missing));
                    Assert.True(missing.IsEmpty);
                },
                record =>
                {
                    Assert.True(record.TryGetAnsiString("Verb", out string expected));
                    Assert.Equal("GET", expected);
                    Assert.Equal(expected.Length, viaRef.Length);

                    // ASCII is a fixed point of every ANSI code page, so the raw bytes and
                    // the decoded characters agree one for one here.
                    for (int i = 0; i < viaRef.Length; i++)
                    {
                        Assert.Equal((byte)expected[i], viaRef[i]);
                    }
                });
        }

        [Fact]
        public void BinaryMatchesTheAllocatingSurface()
        {
            byte[] viaRef = null;

            WithWinINetRecord(
                (in EventRecordRef record) =>
                {
                    Assert.True(record.TryGetBinary("Status", out ReadOnlySpan<byte> value));
                    viaRef = value.ToArray();

                    Assert.False(record.TryGetBinary("Missing", out ReadOnlySpan<byte> missing));
                    Assert.True(missing.IsEmpty);
                },
                record =>
                {
                    Assert.True(record.TryGetBinary("Status", out byte[] expected));
                    Assert.Equal(expected, viaRef);
                });
        }

        [Fact]
        public void RefAccessorsDoNotAllocate()
        {
            WithWinINetRecord((in EventRecordRef record) =>
            {
                long consumed = 0;

                // The first pass warms the schema and property caches and jits the
                // accessors; only the second is measured.
                for (int pass = 0; pass < 2; pass++)
                {
                    long before = GC.GetAllocatedBytesForCurrentThread();

                    for (int i = 0; i < 64; i++)
                    {
                        consumed += record.GetCountedString("URL").Length;
                        record.TryGetAnsiStringBytes("Verb", out ReadOnlySpan<byte> verb);
                        consumed += verb.Length;
                        record.TryGetAnsiStringBytes("URL", out ReadOnlySpan<byte> url);
                        consumed += url.Length;
                        record.TryGetBinary("Status", out ReadOnlySpan<byte> status);
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

        private static void WithPowerShellRecord(string payload, RefAssert refAssert, Action<IEventRecord> compatAssert = null)
        {
            using (var builder = new RecordBuilder(PowerShellProviderId, 7937, 1))
            {
                builder.AddUnicodeString("UserData", "user");
                builder.AddUnicodeString("ContextInfo", "context");
                builder.AddUnicodeString("Payload", payload);

                Push(builder.Pack(), refAssert, compatAssert);
            }
        }

        private static void WithWinINetRecord(RefAssert refAssert, Action<IEventRecord> compatAssert = null)
        {
            using (var builder = new RecordBuilder(WinINetProviderId, 1057, 0))
            {
                builder.AddAnsiString("URL", "http://example.invalid/index.html");
                builder.AddAnsiString("Verb", "GET");
                builder.AddValue("Status", 200u);

                // Later revisions of this event carry header properties this test does not
                // need; pack tolerantly rather than pin the fixture to one Windows build.
                Push(builder.PackIncomplete(), refAssert, compatAssert);
            }
        }

        /// <summary>
        /// Pushes a synthetic record through an <see cref="EventFilter"/> so the callbacks see
        /// the very same record instance a live trace would hand them. The ref handler runs
        /// before the compat handler, matching the dispatch order in production.
        /// </summary>
        private static void Push(SynthRecord record, RefAssert refAssert, Action<IEventRecord> compatAssert)
        {
            var filter = new EventFilter(Filter.AnyEvent());
            Exception failure = null;
            int refSeen = 0;
            int compatSeen = 0;

            filter.OnEventRef += (in EventRecordRef evt) =>
            {
                refSeen++;
                try
                {
                    refAssert(evt);
                }
                catch (Exception ex)
                {
                    failure ??= ex;
                }
            };

            if (compatAssert != null)
            {
                filter.OnEvent += evt =>
                {
                    compatSeen++;
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

            Assert.Equal(1, refSeen);
            Assert.Equal(compatAssert == null ? 0 : 1, compatSeen);

            if (failure != null)
            {
                throw new Xunit.Sdk.XunitException(failure.ToString());
            }
        }
    }
}