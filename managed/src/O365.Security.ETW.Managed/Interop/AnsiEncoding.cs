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
    /// carries TDH_OUTTYPE_UTF8 or TDH_OUTTYPE_JSON -- see <see cref="ForOutType"/> -- which a
    /// sweep of 1503 registered providers (4163 ANSI properties) found zero instances of; every
    /// one was TDH_OUTTYPE_STRING.
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

        /// <summary>
        /// UTF-8 without a byte order mark and without exceptions on malformed input, so a
        /// corrupt payload decodes to replacement characters rather than throwing inside a
        /// trace callback.
        /// </summary>
        private static readonly Encoding Utf8 = new UTF8Encoding(false);

        public static Encoding Current
        {
            get { return Instance; }
        }

        /// <summary>
        /// The encoding an 8-bit string property carries, which its out-type decides.
        /// </summary>
        /// <remarks>
        /// TDH_OUTTYPE_UTF8 and TDH_OUTTYPE_JSON are UTF-8. TDH_OUTTYPE_XML defers to the
        /// document's own encoding declaration, which cannot be honoured without parsing the
        /// value, so it is left on the ANSI code page -- the encoding an XML document without
        /// a declaration would have had on the machine that wrote it.
        /// </remarks>
        public static Encoding ForOutType(ushort outType)
        {
            return IsUtf8(outType) ? Utf8 : Instance;
        }

        /// <summary>
        /// Whether an out-type means the property is UTF-8 rather than ANSI.
        /// </summary>
        public static bool IsUtf8(ushort outType)
        {
            switch ((TdhOutType)outType)
            {
                case TdhOutType.Utf8:
                case TdhOutType.Json:
                    return true;
                default:
                    return false;
            }
        }

        [DllImport("kernel32.dll")]
        private static extern uint GetACP();

        private static Encoding Resolve()
        {
#if NET
            // .NET ships only ASCII, Latin1, UTF-8, UTF-16 and UTF-32 in the box; the rest of
            // the code pages come from this provider. .NET Framework has them all already.
            // This must cover every .NET (Core) target, not just the newest one: without it
            // GetEncoding falls through to the Encoding.Default fallback below, which is UTF-8
            // on .NET, and ANSI properties silently decode with the wrong code page.
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
