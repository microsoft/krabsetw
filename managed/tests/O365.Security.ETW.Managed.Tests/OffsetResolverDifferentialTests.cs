using System;
using System.Collections.Generic;
using Microsoft.O365.Security.ETW.Interop;
using Microsoft.O365.Security.ETW.Schema;
using Xunit;

namespace Microsoft.O365.Security.ETW.Tests
{
    /// <summary>
    /// Asserts that memoised offset resolution is indistinguishable from resolving every
    /// offset from scratch, across randomly shaped schemas and randomly ordered access.
    /// </summary>
    /// <remarks>
    /// krabs resolves offsets from the start of the payload on every property access. This
    /// port memoises them behind a high-water mark, which is a real behavioural difference
    /// that the parity suite cannot see: those tests mirror krabs, so they only exercise
    /// mechanisms krabs has. Any divergence introduced by memoisation therefore has to be
    /// caught here, by differencing the two strategies directly.
    ///
    /// The reference is a fresh resolver per access, which is exactly krabs' model and shares
    /// all of the sizing logic, so this isolates the caching and nothing else.
    /// </remarks>
    public unsafe class OffsetResolverDifferentialTests
    {
        /// <summary>
        /// Fixed seeds rather than a random one: a failure has to be reproducible, and an
        /// intermittently red suite trains people to re-run rather than read.
        /// </summary>
        public static IEnumerable<object[]> Seeds()
        {
            for (int seed = 1; seed <= 200; seed++)
            {
                yield return new object[] { seed };
            }
        }

        [Theory]
        [MemberData(nameof(Seeds))]
        public void MemoisedOffsetsMatchResolvingFromScratch(int seed)
        {
            var random = new Random(seed);

            using (SchemaBlob schema = BuildSchema(random))
            using (var record = new SyntheticRecord(BuildPayload(random)))
            {
                int count = schema.Table.Count;

                foreach (int[] order in AccessOrders(random, count))
                {
                    var shared = new OffsetResolver();
                    shared.Begin(record.Record, schema.Entry);

                    foreach (int index in order)
                    {
                        int fromScratch = ResolveFromScratch(record, schema, index);
                        int memoised = shared.GetOffset(index);

                        Assert.Equal(fromScratch, memoised);
                    }
                }
            }
        }

        /// <summary>
        /// The specific shape that regressed: a property that cannot be sized, read before a
        /// property that precedes it. Kept as an explicit case so the intent survives even if
        /// the generated schemas change.
        /// </summary>
        [Fact]
        public void AnUndecodablePropertyDoesNotRetractEarlierOffsets()
        {
            var builder = new SchemaBlobBuilder()
                .Fixed("first", TdhInType.UInt32, 4)
                .Fixed("second", TdhInType.UInt32, 4)
                .Struct("undecodable")
                .Fixed("last", TdhInType.UInt32, 4);

            using (SchemaBlob schema = builder.Build())
            using (var record = new SyntheticRecord(new byte[16]))
            {
                var shared = new OffsetResolver();
                shared.Begin(record.Record, schema.Entry);

                for (int index = 0; index < schema.Table.Count; index++)
                {
                    Assert.Equal(
                        ResolveFromScratch(record, schema, index),
                        shared.GetOffset(index));
                }
            }
        }

        /// <summary>
        /// Guards against the generated corpus quietly degenerating into schemas where every
        /// lookup fails, which would make the differential assertions pass vacuously.
        /// </summary>
        [Fact]
        public void TheGeneratedCorpusResolvesAndFailsInMeaningfulProportions()
        {
            int resolved = 0;
            int failed = 0;

            for (int seed = 1; seed <= 200; seed++)
            {
                var random = new Random(seed);

                using (SchemaBlob schema = BuildSchema(random))
                using (var record = new SyntheticRecord(BuildPayload(random)))
                {
                    for (int index = 0; index < schema.Table.Count; index++)
                    {
                        if (ResolveFromScratch(record, schema, index) < 0)
                        {
                            failed++;
                        }
                        else
                        {
                            resolved++;
                        }
                    }
                }
            }

            Assert.True(resolved > 200, "expected many resolvable offsets, got " + resolved);
            Assert.True(failed > 200, "expected many unresolvable offsets, got " + failed);
        }

        /// <summary>Resolves one offset with a resolver that has memoised nothing, as krabs does.</summary>
        private static int ResolveFromScratch(SyntheticRecord record, SchemaBlob schema, int index)
        {
            var resolver = new OffsetResolver();
            resolver.Begin(record.Record, schema.Entry);
            return resolver.GetOffset(index);
        }

        private static IEnumerable<int[]> AccessOrders(Random random, int count)
        {
            var forward = new int[count];
            for (int i = 0; i < count; i++)
            {
                forward[i] = i;
            }

            yield return forward;

            var reverse = new int[count];
            for (int i = 0; i < count; i++)
            {
                reverse[i] = count - 1 - i;
            }

            yield return reverse;

            for (int attempt = 0; attempt < 4; attempt++)
            {
                var shuffled = (int[])forward.Clone();
                for (int i = shuffled.Length - 1; i > 0; i--)
                {
                    int j = random.Next(i + 1);
                    int swap = shuffled[i];
                    shuffled[i] = shuffled[j];
                    shuffled[j] = swap;
                }

                yield return shuffled;
            }

            // Repeated reads of the same index must be stable, not just correct once.
            var repeated = new int[count * 2];
            for (int i = 0; i < repeated.Length; i++)
            {
                repeated[i] = random.Next(count);
            }

            yield return repeated;
        }

        private static SchemaBlob BuildSchema(Random random)
        {
            int count = random.Next(3, 9);
            var builder = new SchemaBlobBuilder();
            int lastFixedIndex = -1;

            for (int i = 0; i < count; i++)
            {
                string name = "p" + i;

                // Weighted so most schemas stay decodable end to end, while structs and
                // payload-derived lengths still show up often enough to matter.
                switch (random.Next(10))
                {
                    case 0:
                    case 1:
                        builder.Fixed(name, TdhInType.UInt32, 4);
                        lastFixedIndex = i;
                        break;

                    case 2:
                        builder.Fixed(name, TdhInType.UInt8, 1);
                        lastFixedIndex = i;
                        break;

                    case 3:
                        builder.Fixed(name, TdhInType.UInt64, 8);
                        lastFixedIndex = i;
                        break;

                    case 4:
                    case 5:
                        builder.NullTerminated(name, TdhInType.UnicodeString);
                        break;

                    case 6:
                        builder.NullTerminated(name, TdhInType.AnsiString);
                        break;

                    case 7:
                        builder.Struct(name);
                        break;

                    case 8:
                        if (lastFixedIndex >= 0)
                        {
                            builder.ParamLength(name, TdhInType.Binary, lastFixedIndex);
                        }
                        else
                        {
                            builder.Fixed(name, TdhInType.UInt16, 2);
                            lastFixedIndex = i;
                        }

                        break;

                    default:
                        builder.Fixed(name, TdhInType.Guid, 16);
                        lastFixedIndex = i;
                        break;
                }
            }

            return builder.Build();
        }

        private static byte[] BuildPayload(Random random)
        {
            // Deliberately includes payloads too short for the schema, so the walk stalls part
            // way through and the sticky failure state gets exercised.
            var payload = new byte[random.Next(0, 48)];
            random.NextBytes(payload);
            return payload;
        }
    }
}
