using System;
using System.Runtime.InteropServices;
using Microsoft.O365.Security.ETW.Interop;
using Microsoft.O365.Security.ETW.Schema;
using Xunit;

namespace Microsoft.O365.Security.ETW.Tests
{
    /// <summary>
    /// Covers the one-entry memo in front of the schema dictionary.
    /// </summary>
    /// <remarks>
    /// The memo answers from the previous event's schema when the current event looks like the
    /// same kind of event. It decides that with a hand written field-by-field comparison, so a
    /// field omitted from <c>SchemaKey.MatchesEvent</c> would silently decode one event with
    /// another's schema -- no exception, no failed lookup, just wrong values. These tests vary
    /// one identity field at a time so a dropped comparison fails loudly.
    ///
    /// The records are synthetic, so TDH cannot describe them and every schema resolves to a
    /// cached failure. That is deliberate: identity is what is under test, and a cached failure
    /// is still a distinct object per key, which is what the assertions rely on.
    /// </remarks>
    public unsafe class SchemaCacheTests : IDisposable
    {
        private static readonly Guid ProviderA = new Guid("11111111-1111-1111-1111-111111111111");
        private static readonly Guid ProviderB = new Guid("22222222-2222-2222-2222-222222222222");

        private readonly SchemaCache _cache = new SchemaCache();

        [Fact]
        public void RepeatingAnEventAnswersFromTheMemo()
        {
            using (var record = Record())
            {
                SchemaEntry first = _cache.Get(record.Record);
                int missesAfterFirst = _cache.Misses;

                Assert.Same(first, _cache.Get(record.Record));
                Assert.Same(first, _cache.Get(record.Record));
                Assert.Equal(missesAfterFirst, _cache.Misses);
            }
        }

        [Fact]
        public void AlternatingBetweenTwoEventsStillResolvesEachToItsOwnSchema()
        {
            using (var a = Record(id: 1))
            using (var b = Record(id: 2))
            {
                SchemaEntry first = _cache.Get(a.Record);
                SchemaEntry second = _cache.Get(b.Record);

                Assert.NotSame(first, second);

                // The memo misses on every event here, so this also proves the dictionary
                // behind it keeps both schemas rather than thrashing.
                int misses = _cache.Misses;

                for (int i = 0; i < 8; i++)
                {
                    Assert.Same(first, _cache.Get(a.Record));
                    Assert.Same(second, _cache.Get(b.Record));
                }

                Assert.Equal(misses, _cache.Misses);
            }
        }

        [Theory]
        [InlineData("id")]
        [InlineData("version")]
        [InlineData("opcode")]
        [InlineData("level")]
        [InlineData("keyword")]
        [InlineData("provider")]
        public void EventsDifferingOnlyInOneIdentityFieldGetDifferentSchemas(string field)
        {
            using (SyntheticEvent a = Record())
            using (SyntheticEvent b = Vary(field))
            {
                SchemaEntry first = _cache.Get(a.Record);
                SchemaEntry second = _cache.Get(b.Record);

                Assert.NotSame(first, second);

                // Going back to the first event must not answer with the second's schema,
                // which is what a too-permissive memo comparison would do.
                Assert.Same(first, _cache.Get(a.Record));
            }
        }

        private static SyntheticEvent Vary(string field)
        {
            switch (field)
            {
                case "id": return Record(id: 99);
                case "version": return Record(version: 9);
                case "opcode": return Record(opcode: 9);
                case "level": return Record(level: 9);
                case "keyword": return Record(keyword: 0x99);
                case "provider": return Record(provider: ProviderB);
                default: throw new ArgumentOutOfRangeException(nameof(field));
            }
        }

        private static SyntheticEvent Record(
            Guid? provider = null,
            ushort id = 1,
            byte version = 1,
            byte opcode = 1,
            byte level = 1,
            ulong keyword = 0x1)
        {
            return new SyntheticEvent(provider ?? ProviderA, id, version, opcode, level, keyword);
        }

        public void Dispose()
        {
            _cache.Dispose();
        }

        private sealed class SyntheticEvent : IDisposable
        {
            private IntPtr _record;

            public SyntheticEvent(Guid provider, ushort id, byte version, byte opcode, byte level, ulong keyword)
            {
                _record = Marshal.AllocHGlobal(sizeof(EVENT_RECORD));

                var record = (EVENT_RECORD*)_record;
                *record = default(EVENT_RECORD);
                record->EventHeader.ProviderId = provider;
                record->EventHeader.Flags = NativeConstants.EVENT_HEADER_FLAG_64_BIT_HEADER;
                record->EventHeader.EventDescriptor.Id = id;
                record->EventHeader.EventDescriptor.Version = version;
                record->EventHeader.EventDescriptor.Opcode = opcode;
                record->EventHeader.EventDescriptor.Level = level;
                record->EventHeader.EventDescriptor.Keyword = keyword;
            }

            public EVENT_RECORD* Record
            {
                get { return (EVENT_RECORD*)_record; }
            }

            public void Dispose()
            {
                if (_record != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(_record);
                    _record = IntPtr.Zero;
                }
            }
        }
    }
}
