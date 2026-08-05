using Microsoft.O365.Security.ETW.Interop;
using Microsoft.O365.Security.ETW.Schema;
using Xunit;

namespace Microsoft.O365.Security.ETW.Tests
{
    /// <summary>
    /// Covers property lookup by name: the scan hint and the name signature.
    /// </summary>
    /// <remarks>
    /// Both are pure optimisations that must not be observable. The signature is a cheap
    /// fixed-cost filter (length, first, middle and last character) rather than a real hash,
    /// so it collides by design and correctness rests entirely on the full name comparison
    /// that follows. The hint carries over between lookups and between events, so it also has
    /// to be impossible for it to make a lookup miss a property it should have found.
    /// </remarks>
    public unsafe class PropertyTableTests
    {
        /// <summary>
        /// These names collide: same length, same first, middle and last character. If the
        /// confirming comparison were ever dropped, this is what would break.
        /// </summary>
        private const string Collides1 = "abcde";
        private const string Collides2 = "aXcde";

        [Fact]
        public void NamesThatShareASignatureAreStillToldApart()
        {
            Assert.Equal(
                NameSignature.Compute(Collides1.AsSpanCompat()),
                NameSignature.Compute(Collides2.AsSpanCompat()));

            var builder = new SchemaBlobBuilder()
                .Fixed(Collides1, TdhInType.UInt32, 4)
                .Fixed(Collides2, TdhInType.UInt32, 4);

            using (SchemaBlob schema = builder.Build())
            {
                Assert.Equal(0, schema.Table.IndexOf(Collides1.AsSpanCompat(), schema.Pointer));
                Assert.Equal(1, schema.Table.IndexOf(Collides2.AsSpanCompat(), schema.Pointer));

                // Reversed, so the hint points away from the answer both times.
                Assert.Equal(1, schema.Table.IndexOf(Collides2.AsSpanCompat(), schema.Pointer));
                Assert.Equal(0, schema.Table.IndexOf(Collides1.AsSpanCompat(), schema.Pointer));
            }
        }

        [Fact]
        public void EveryPropertyIsFoundFromEveryHintPosition()
        {
            var builder = new SchemaBlobBuilder();
            var names = new[] { "alpha", "b", "gamma", "d", "epsilon", "zeta", "aXcde", "abcde" };

            foreach (string name in names)
            {
                builder.Fixed(name, TdhInType.UInt32, 4);
            }

            using (SchemaBlob schema = builder.Build())
            {
                // Walking every start position leaves the hint everywhere in turn, so this
                // covers the wrap-around in the scan as well.
                for (int start = 0; start < names.Length; start++)
                {
                    schema.Table.IndexOf(names[start].AsSpanCompat(), schema.Pointer);

                    for (int i = 0; i < names.Length; i++)
                    {
                        Assert.Equal(i, schema.Table.IndexOf(names[i].AsSpanCompat(), schema.Pointer));
                    }
                }
            }
        }

        [Fact]
        public void AnUnknownNameIsReportedMissingRegardlessOfTheHint()
        {
            var builder = new SchemaBlobBuilder()
                .Fixed("alpha", TdhInType.UInt32, 4)
                .Fixed("beta", TdhInType.UInt32, 4)
                .Fixed("gamma", TdhInType.UInt32, 4);

            using (SchemaBlob schema = builder.Build())
            {
                for (int start = 0; start < schema.Table.Count; start++)
                {
                    schema.Table.IndexOf(("alpha" + start).AsSpanCompat(), schema.Pointer);

                    Assert.Equal(-1, schema.Table.IndexOf("delta".AsSpanCompat(), schema.Pointer));

                    // Same length and same first/middle/last as "gamma", so it survives the
                    // signature filter and can only be rejected by the name comparison.
                    Assert.Equal(-1, schema.Table.IndexOf("gaXma".AsSpanCompat(), schema.Pointer));
                }
            }
        }

        [Fact]
        public void NamesDifferingOnlyInLengthDoNotMatch()
        {
            var builder = new SchemaBlobBuilder()
                .Fixed("abc", TdhInType.UInt32, 4)
                .Fixed("abcd", TdhInType.UInt32, 4);

            using (SchemaBlob schema = builder.Build())
            {
                Assert.Equal(0, schema.Table.IndexOf("abc".AsSpanCompat(), schema.Pointer));
                Assert.Equal(1, schema.Table.IndexOf("abcd".AsSpanCompat(), schema.Pointer));
                Assert.Equal(-1, schema.Table.IndexOf("ab".AsSpanCompat(), schema.Pointer));
            }
        }

        [Fact]
        public void TheEmptyNameIsDistinctFromAnUnnamedProperty()
        {
            // Unnamed properties store a zero signature, so the empty string must not compute
            // to zero or it would match them.
            Assert.NotEqual(0UL, NameSignature.Compute(string.Empty.AsSpanCompat()));
        }
    }

    internal static class SpanCompat
    {
        /// <summary>string.AsSpan() is not available on every target framework here.</summary>
        public static System.ReadOnlySpan<char> AsSpanCompat(this string value)
        {
            return value.ToCharArray();
        }
    }
}
