using System;
using System.Runtime.InteropServices;
using Microsoft.O365.Security.ETW.Schema;
using Xunit;

namespace Microsoft.O365.Security.ETW.Tests
{
    /// <summary>
    /// Pins the layout of <see cref="PropertyInfo"/>.
    /// </summary>
    /// <remarks>
    /// The struct replaced nine parallel arrays, which cost nine object headers per cached
    /// schema — 400 bytes to hold about 64 bytes of data for the median two-property event.
    /// It is 24 bytes with no padding, but only because the fields are ordered widest-first.
    /// There is no <c>Pack</c> attribute, so a field added out of order would be padded rather
    /// than misaligned; this test exists so that shows up as a size change instead of silently
    /// growing every cache entry.
    /// </remarks>
    public class PropertyInfoLayoutTests
    {
        [Fact]
        public unsafe void IsTwentyFourBytes()
        {
            Assert.Equal(24, sizeof(PropertyInfo));
        }

        [Theory]
        [InlineData("NameOffset", 0, 4)]
        [InlineData("NameLength", 4, 4)]
        [InlineData("FixedOffset", 8, 4)]
        [InlineData("Flags", 12, 4)]
        [InlineData("InType", 16, 2)]
        [InlineData("OutType", 18, 2)]
        [InlineData("Length", 20, 2)]
        [InlineData("Count", 22, 2)]
        public void EveryFieldIsNaturallyAligned(string field, int expectedOffset, int width)
        {
            int offset = (int)Marshal.OffsetOf<PropertyInfo>(field);

            Assert.Equal(expectedOffset, offset);
            Assert.Equal(0, offset % width);
        }

        /// <summary>
        /// Field alignment within the struct only matters if the elements themselves are
        /// aligned, which the stride decides.
        /// </summary>
        [Fact]
        public unsafe void ArrayElementsStayAligned()
        {
            var array = new PropertyInfo[4];

            fixed (PropertyInfo* p = array)
            {
                long stride = (long)(p + 1) - (long)p;

                Assert.Equal(24, stride);

                // 24 is a multiple of 8, so every element keeps the base allocation's
                // alignment rather than drifting onto odd boundaries.
                Assert.Equal(0, stride % 8);

                for (int i = 0; i < array.Length; i++)
                {
                    Assert.Equal(0, (long)(p + i) % 4);
                }
            }
        }
    }
}
