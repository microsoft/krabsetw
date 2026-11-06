using System.Text;
using Microsoft.O365.Security.ETW.Interop;
using Xunit;

namespace Microsoft.O365.Security.ETW.Tests
{
    /// <summary>
    /// Pins how ANSI string properties are decoded.
    /// </summary>
    /// <remarks>
    /// tdh.h, TDH_OUTTYPE_STRING: ANSISTRING data "is decoded using the ANSI code page of the
    /// event provider". A sweep of every provider registered on a build machine found 4163
    /// ANSI-typed properties, 4162 of them TDH_OUTTYPE_STRING and none TDH_OUTTYPE_UTF8 -- so
    /// the ANSI code page is not an edge case, it is the only case that occurs.
    ///
    /// The port originally decoded these as UTF-8, which turned every non-ASCII byte in a URL,
    /// HTTP header or command line into U+FFFD. That is lossy, so it needs a test that fails
    /// if anyone reaches for Encoding.UTF8 or Encoding.Default here again -- Encoding.Default
    /// being the subtler trap, since it is CP_ACP on .NET Framework but UTF-8 on .NET.
    /// </remarks>
    public class AnsiEncodingTests
    {
        [Fact]
        public void UsesTheMachineAnsiCodePage()
        {
            Assert.Equal(GetACPCodePage(), AnsiEncoding.Current.CodePage);
        }

        [Fact]
        public void IsIdenticalToUtf8ForAscii()
        {
            const string Ascii = "GET /index.html HTTP/1.1";

            Assert.Equal(Encoding.UTF8.GetBytes(Ascii), AnsiEncoding.Current.GetBytes(Ascii));
        }

        /// <summary>
        /// The regression itself: bytes that are valid in the ANSI code page but not valid
        /// UTF-8 must survive a round trip rather than collapsing to replacement characters.
        /// </summary>
        [Fact]
        public void RoundTripsBytesThatAreNotValidUtf8()
        {
            if (AnsiEncoding.Current.CodePage == 65001)
            {
                // The machine is configured for UTF-8, so there is no distinction to test.
                return;
            }

            // 0xE9 is 'e' with an acute accent in the Windows Latin code pages, and an
            // incomplete sequence in UTF-8.
            var raw = new byte[] { (byte)'c', (byte)'a', (byte)'f', 0xE9 };

            string ansi = AnsiEncoding.Current.GetString(raw);
            string utf8 = Encoding.UTF8.GetString(raw);

            Assert.DoesNotContain('\uFFFD', ansi);
            Assert.Contains('\uFFFD', utf8);
            Assert.Equal(raw, AnsiEncoding.Current.GetBytes(ansi));
        }

        private static int GetACPCodePage()
        {
            // Read from the OS rather than repeating the implementation's own lookup.
            return int.Parse(
                Microsoft.Win32.Registry.GetValue(
                    @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Nls\CodePage",
                    "ACP",
                    "1252").ToString());
        }
    }
}
