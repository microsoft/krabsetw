using System;
using System.Runtime.InteropServices;
using System.Text;

namespace Microsoft.O365.Security.ETW.Interop
{
    /// <summary>
    /// The encoding used for TDH ANSI string properties.
    /// </summary>
    /// <remarks>
    /// tdh.h, TDH_OUTTYPE_STRING: "For INT8, UINT8, and ANSISTRING InTypes, the data is decoded
    /// using the ANSI code page of the event provider." UTF-8 applies only when the property
    /// carries TDH_OUTTYPE_UTF8 or TDH_OUTTYPE_JSON, which a sweep of 1503 registered providers
    /// (4163 ANSI properties) found zero instances of -- every one was TDH_OUTTYPE_STRING.
    ///
    /// This also matches the C++/CLI wrapper, which builds these strings with
    /// gcnew String(str.c_str()) and so converts through CP_ACP.
    ///
    /// Encoding.Default is not usable here: it is CP_ACP on .NET Framework but UTF-8 on .NET,
    /// so it would make the two target frameworks disagree with each other. GetACP is asked
    /// directly instead.
    /// </remarks>
    internal static class AnsiEncoding
    {
        private static readonly Encoding Instance = Resolve();

        public static Encoding Current
        {
            get { return Instance; }
        }

        [DllImport("kernel32.dll")]
        private static extern uint GetACP();

        private static Encoding Resolve()
        {
#if NET10_0_OR_GREATER
            // .NET ships only ASCII, Latin1, UTF-8, UTF-16 and UTF-32 in the box; the rest of
            // the code pages come from this provider. .NET Framework has them all already.
            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
#endif

            try
            {
                return Encoding.GetEncoding((int)GetACP());
            }
            catch (ArgumentException)
            {
                return Encoding.Default;
            }
            catch (NotSupportedException)
            {
                return Encoding.Default;
            }
        }
    }
}
