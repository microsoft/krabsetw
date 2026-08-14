using System;
using System.Runtime.CompilerServices;

namespace Microsoft.O365.Security.ETW.Interop
{
    /// <summary>
    /// Comparison helpers for types the framework compares more slowly than it needs to.
    /// </summary>
    internal static unsafe class Blit
    {
        /// <summary>
        /// Compares two GUIDs as sixteen bytes.
        /// </summary>
        /// <remarks>
        /// .NET Framework's Guid.Equals compares the eleven fields of the struct one at a
        /// time. A GUID is sixteen contiguous bytes with no padding, so two 64-bit compares
        /// answer the same question. This runs for every event, once per enabled provider
        /// while routing and once more against the cached schema key, so it is worth not
        /// paying eleven branches for.
        /// </remarks>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static bool GuidEquals(Guid left, Guid right)
        {
            // Both are locals, so neither can move and neither needs pinning.
            ulong* l = (ulong*)&left;
            ulong* r = (ulong*)&right;

            return l[0] == r[0] && l[1] == r[1];
        }
    }
}
