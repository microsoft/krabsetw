using System;
using System.Runtime.CompilerServices;

namespace Microsoft.O365.Security.ETW.Interop
{
    /// <summary>
    /// A GUID held as the two 64-bit halves its sixteen bytes are made of.
    /// </summary>
    /// <remarks>
    /// Every event compares GUIDs -- once per enabled provider while routing, and once more
    /// against the cached schema key -- and doing that through System.Guid costs more than
    /// the comparison. .NET Framework's Guid.Equals walks the eleven fields of the struct one
    /// at a time. Reading the halves instead means taking the address of a Guid, which homes
    /// it on the stack and copies sixteen bytes at every hand-off: out of the event header
    /// into a local, into the callee, and again for the value being compared against.
    ///
    /// Splitting once, when the provider set is published and when a schema key is built,
    /// removes all of that from the per-event path: what is compared is already two ulongs,
    /// so the JIT can keep them in registers.
    ///
    /// The halves are the raw bytes in memory order, not the field values Guid exposes, so
    /// they are only meaningful against halves taken the same way. Nothing here should be
    /// persisted, logged, or compared against a GUID from any other source.
    /// </remarks>
    internal readonly unsafe struct GuidKey : IEquatable<GuidKey>
    {
        public readonly ulong Lo;
        public readonly ulong Hi;

        public GuidKey(Guid value)
        {
            // A local, so it cannot move and needs no pinning.
            ulong* p = (ulong*)&value;
            Lo = p[0];
            Hi = p[1];
        }

        private GuidKey(ulong lo, ulong hi)
        {
            Lo = lo;
            Hi = hi;
        }

        /// <summary>
        /// Reads the halves of a GUID that already lives in unmanaged memory, without
        /// copying it into a Guid first.
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static GuidKey Read(Guid* value)
        {
            ulong* p = (ulong*)value;
            return new GuidKey(p[0], p[1]);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public bool Equals(GuidKey other)
        {
            return Lo == other.Lo && Hi == other.Hi;
        }

        public override bool Equals(object? obj)
        {
            return obj is GuidKey other && Equals(other);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                ulong mixed = Lo ^ Hi;
                return (int)mixed ^ (int)(mixed >> 32);
            }
        }
    }
}
