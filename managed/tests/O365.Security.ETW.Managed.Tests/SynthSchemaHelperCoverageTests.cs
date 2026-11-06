using System;
using Microsoft.O365.Security.ETW;
using Microsoft.O365.Security.ETW.Schema;
using Xunit;

namespace Microsoft.O365.Security.ETW.Tests
{
    /// <summary>
    /// Covers schema helpers that are internal implementation details of synthetic dispatch.
    /// </summary>
    /// <remarks>
    /// The helpers are not part of the consumer API, but synthetic record dispatch depends on
    /// their invariants: zero-byte scans must stop at the first terminator.
    /// </remarks>
    public unsafe class SynthSchemaHelperCoverageTests
    {
        [Fact]
        public void ShortSpanFindsTheFirstZeroByteOrReportsThatNoneExists()
        {
            byte[] withZero = { 7, 6, 0, 5, 0 };
            fixed (byte* p = withZero)
            {
                Assert.Equal(2, ShortSpan.IndexOfZero(p, withZero.Length));
                Assert.Equal(-1, ShortSpan.IndexOfZero(p, 2));
            }

            byte[] withoutZero = { 1, 2, 3 };
            fixed (byte* p = withoutZero)
            {
                Assert.Equal(-1, ShortSpan.IndexOfZero(p, withoutZero.Length));
            }
        }
    }
}
