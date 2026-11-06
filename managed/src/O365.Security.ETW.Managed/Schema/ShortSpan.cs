using System;
using System.Runtime.CompilerServices;

namespace Microsoft.O365.Security.ETW.Schema
{
    /// <summary>
    /// Short-span comparison helpers for the per-event path, specialised per runtime.
    /// </summary>
    /// <remarks>
    /// On .NET the vectorised <see cref="MemoryExtensions"/> routines are the fastest option
    /// even for the handful of characters an event or property name occupies, so they are
    /// used directly.
    ///
    /// On .NET Framework the same methods come from the System.Memory package, where they are
    /// markedly more expensive: measured on the property-lookup path, SequenceEqual alone cost
    /// several times what the naive loop does, because the vector setup never pays for itself
    /// at these lengths. There the loops below are used instead.
    /// </remarks>
    internal static unsafe class ShortSpan
    {
        /// <summary>Index of the first zero byte, or -1.</summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static int IndexOfZero(byte* data, int length)
        {
#if NET10_0_OR_GREATER
            return new ReadOnlySpan<byte>(data, length).IndexOf((byte)0);
#else
            for (int i = 0; i < length; i++)
            {
                if (data[i] == 0)
                {
                    return i;
                }
            }

            return -1;
#endif
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static bool Equal(ReadOnlySpan<byte> left, byte[] right)
        {
#if NET10_0_OR_GREATER
            return left.SequenceEqual(right);
#else
            if (left.Length != right.Length)
            {
                return false;
            }

            for (int i = 0; i < right.Length; i++)
            {
                if (left[i] != right[i])
                {
                    return false;
                }
            }

            return true;
#endif
        }

        /// <summary>
        /// Compares a name held in the schema blob against a caller-supplied name already
        /// known to be the same length.
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static bool Equal(char* left, ReadOnlySpan<char> right)
        {
#if NET10_0_OR_GREATER
            return new ReadOnlySpan<char>(left, right.Length).SequenceEqual(right);
#else
            for (int i = 0; i < right.Length; i++)
            {
                if (left[i] != right[i])
                {
                    return false;
                }
            }

            return true;
#endif
        }
    }
}
