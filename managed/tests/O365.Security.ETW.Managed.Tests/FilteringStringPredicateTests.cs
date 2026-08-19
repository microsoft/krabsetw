using System;
using Microsoft.O365.Security.ETW.Testing;
using Xunit;

namespace Microsoft.O365.Security.ETW.Tests
{
    /// <summary>
    /// Covers string filter predicates against synthetic records, including the span
    /// comparison cases they rely on.
    /// </summary>
    public class FilteringStringPredicateTests
    {
        private static readonly Guid ProviderId = Guid.Parse("39d6de67-13d6-4f6a-a69c-22c479e2a4d6");

        [Theory]
        [InlineData("alpha", "alpha", true)]
        [InlineData("alpha", "ALPHA", false)]
        [InlineData("alpha", "", false)]
        [InlineData("", "", true)]
        public void UnicodeIsComparesTheWholeValueCaseSensitively(string actual, string expected, bool matches)
        {
            Assert.Equal(matches, Test(UnicodeString.Is("Text", expected), actual));
        }

        [Theory]
        [InlineData("alphabet", "PHAB", true)]
        [InlineData("alphabet", "PHz", false)]
        [InlineData("alphabet", "", true)]
        [InlineData("short", "longer-than-short", false)]
        public void UnicodeIContainsFindsCaseInsensitiveNeedlesAndRejectsMismatches(string actual, string expected, bool matches)
        {
            Assert.Equal(matches, Test(UnicodeString.IContains("Text", expected), actual));
        }

        [Theory]
        [InlineData("alphabet", "ALP", true)]
        [InlineData("alphabet", "BET", false)]
        [InlineData("alphabet", "alphabetical", false)]
        [InlineData("éclair", "ÉC", true)]
        public void UnicodeIStartsWithChecksOnlyThePrefix(string actual, string expected, bool matches)
        {
            Assert.Equal(matches, Test(UnicodeString.IStartsWith("Text", expected), actual));
        }

        [Theory]
        [InlineData("alphabet", "BET", true)]
        [InlineData("alphabet", "ALP", false)]
        [InlineData("alphabet", "the-alphabet", false)]
        public void UnicodeIEndsWithChecksOnlyTheSuffix(string actual, string expected, bool matches)
        {
            Assert.Equal(matches, Test(UnicodeString.IEndsWith("Text", expected), actual));
        }

        [Fact]
        public void UnicodePredicatesReturnFalseWhenThePropertyIsAbsent()
        {
            Assert.False(Test(UnicodeString.Is("Missing", "value"), "value"));
        }

        [Fact]
        public void UnicodeFactoryMethodsCreatePredicatesForEachMatchKind()
        {
            Assert.True(Test(UnicodeString.IEquals("Text", "ALPHA"), "alpha"));
            Assert.True(Test(UnicodeString.Contains("Text", "ph"), "alpha"));
            Assert.True(Test(UnicodeString.StartsWith("Text", "al"), "alpha"));
            Assert.True(Test(UnicodeString.EndsWith("Text", "ha"), "alpha"));
        }

        [Theory]
        [InlineData("abcd", "abcd", true)]
        [InlineData("abcd", "ABCD", true)]
        [InlineData("abcd", "bc", false)]
        [InlineData("abcd", "AB", false)]
        [InlineData("abcd", "CD", false)]
        [InlineData("abcd", "ac", false)]
        public void CountedStringIEqualsStripsTheCountPrefixBeforeComparing(string actual, string expected, bool matches)
        {
            Assert.Equal(matches, Test(CountedString.IEquals("Text", expected), Counted(actual)));
        }

        [Theory]
        [InlineData("abcd", "abcd", true)]
        [InlineData("abcd", "ABCD", true)]
        [InlineData("abcd", "bc", true)]
        [InlineData("abcd", "AB", true)]
        [InlineData("abcd", "CD", true)]
        [InlineData("abcd", "ac", false)]
        public void CountedStringIContainsStripsTheCountPrefixBeforeComparing(string actual, string expected, bool matches)
        {
            Assert.Equal(matches, Test(CountedString.IContains("Text", expected), Counted(actual)));
        }

        [Theory]
        [InlineData("abcd", "abcd", true)]
        [InlineData("abcd", "ABCD", true)]
        [InlineData("abcd", "bc", false)]
        [InlineData("abcd", "AB", true)]
        [InlineData("abcd", "CD", false)]
        [InlineData("abcd", "ac", false)]
        public void CountedStringIStartsWithStripsTheCountPrefixBeforeComparing(string actual, string expected, bool matches)
        {
            Assert.Equal(matches, Test(CountedString.IStartsWith("Text", expected), Counted(actual)));
        }

        [Theory]
        [InlineData("abcd", "abcd", true)]
        [InlineData("abcd", "ABCD", true)]
        [InlineData("abcd", "bc", false)]
        [InlineData("abcd", "AB", false)]
        [InlineData("abcd", "CD", true)]
        [InlineData("abcd", "ac", false)]
        public void CountedStringIEndsWithStripsTheCountPrefixBeforeComparing(string actual, string expected, bool matches)
        {
            Assert.Equal(matches, Test(CountedString.IEndsWith("Text", expected), Counted(actual)));
        }

        [Fact]
        public void CountedStringPredicatesReturnFalseWhenThePropertyIsAbsent()
        {
            Assert.False(Test(CountedString.Is("Missing", "abcd"), Counted("abcd")));
        }

        [Fact]
        public void CountedStringFactoryMethodsCreatePredicatesForEachMatchKind()
        {
            Assert.True(Test(CountedString.Is("Text", "abcd"), Counted("abcd")));
            Assert.True(Test(CountedString.Contains("Text", "bc"), Counted("abcd")));
            Assert.True(Test(CountedString.StartsWith("Text", "ab"), Counted("abcd")));
            Assert.True(Test(CountedString.EndsWith("Text", "cd"), Counted("abcd")));
        }

        [Fact]
        public void AnsiPredicatesComparePayloadBytesWithOrdinalAsciiCaseRules()
        {
            Assert.True(Test(AnsiString.Is("Text", "GET /index.html"), "GET /index.html", ansi: true));
            Assert.False(Test(AnsiString.Is("Text", "get /index.html"), "GET /index.html", ansi: true));
            Assert.True(Test(AnsiString.Contains("Text", "/index"), "GET /index.html", ansi: true));
            Assert.False(Test(AnsiString.Contains("Text", "POST"), "GET /index.html", ansi: true));
            Assert.True(Test(AnsiString.IStartsWith("Text", "get"), "GET /index.html", ansi: true));
            Assert.False(Test(AnsiString.IStartsWith("Text", "POST"), "GET /index.html", ansi: true));
            Assert.True(Test(AnsiString.IEndsWith("Text", ".HTML"), "GET /index.html", ansi: true));
            Assert.False(Test(AnsiString.IEndsWith("Text", ".png"), "GET /index.html", ansi: true));
        }

        [Fact]
        public void AnsiPredicateUsesUtf8BytesWhenTheSchemaDeclaresUtf8()
        {
            Assert.True(Test(AnsiString.Is("Text", "café"), "café", ansi: true, utf8: true));
            Assert.False(Test(AnsiString.Is("Text", "cafe"), "café", ansi: true, utf8: true));
        }

        [Fact]
        public void AnsiPredicatesReturnFalseWhenThePropertyIsAbsent()
        {
            Assert.False(Test(AnsiString.Is("Missing", "GET"), "GET", ansi: true));
        }

        [Fact]
        public void AnsiStringFactoryMethodsCreatePredicatesForEachMatchKind()
        {
            Assert.True(Test(AnsiString.IEquals("Text", "get"), "GET", ansi: true));
            Assert.True(Test(AnsiString.IContains("Text", "INDE"), "GET /index.html", ansi: true));
            Assert.True(Test(AnsiString.StartsWith("Text", "GET"), "GET /index.html", ansi: true));
            Assert.True(Test(AnsiString.EndsWith("Text", ".html"), "GET /index.html", ansi: true));
        }

        private static bool Test(Predicate predicate, string text, bool ansi = false, bool utf8 = false)
        {
            EventSchema schema = EventSchema
                .Create("Filtering-String-Predicate-Provider", ProviderId, id: ansi ? 2 : 1)
                .Named("Payload")
                .UInt32("ProcessId");

            schema = utf8 ? schema.Utf8String("Text") : ansi ? schema.AnsiString("Text") : schema.UnicodeString("Text");

            using (EventSchema.Use(schema))
            using (var builder = new RecordBuilder(ProviderId, id: ansi ? 2 : 1, version: 0))
            {
                builder.AddValue("ProcessId", 1234u);
                if (ansi)
                {
                    builder.AddAnsiString("Text", text);
                }
                else
                {
                    builder.AddUnicodeString("Text", text);
                }

                using (SynthRecord record = builder.Pack())
                {
                    return predicate.Test(record);
                }
            }
        }

        private static string Counted(string value)
        {
            return ((char)(value.Length * 2)) + value;
        }
    }
}
