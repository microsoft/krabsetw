using System;

namespace O365.Security.ETW
{
    /// <summary>
    /// Ordinal span comparisons, with an ignore-case variant that behaves identically on
    /// every target framework.
    /// </summary>
    /// <remarks>
    /// These exist rather than <c>MemoryExtensions</c> overloads taking a
    /// <see cref="StringComparison"/> because the set of those overloads differs between
    /// .NET Framework (via System.Memory) and .NET 10, and a filter must not change meaning
    /// depending on which one the process loaded.
    /// </remarks>
    internal static class SpanCompare
    {
        public static bool Equals(ReadOnlySpan<char> value, ReadOnlySpan<char> other, bool ignoreCase)
        {
            if (value.Length != other.Length)
            {
                return false;
            }

            if (!ignoreCase)
            {
                return value.SequenceEqual(other);
            }

            for (int i = 0; i < value.Length; i++)
            {
                if (ToUpper(value[i]) != ToUpper(other[i]))
                {
                    return false;
                }
            }

            return true;
        }

        public static bool StartsWith(ReadOnlySpan<char> value, ReadOnlySpan<char> prefix, bool ignoreCase)
        {
            return prefix.Length <= value.Length
                && Equals(value.Slice(0, prefix.Length), prefix, ignoreCase);
        }

        public static bool EndsWith(ReadOnlySpan<char> value, ReadOnlySpan<char> suffix, bool ignoreCase)
        {
            return suffix.Length <= value.Length
                && Equals(value.Slice(value.Length - suffix.Length), suffix, ignoreCase);
        }

        public static bool Contains(ReadOnlySpan<char> value, ReadOnlySpan<char> needle, bool ignoreCase)
        {
            if (needle.Length == 0)
            {
                return true;
            }

            if (needle.Length > value.Length)
            {
                return false;
            }

            if (!ignoreCase)
            {
                return value.IndexOf(needle) >= 0;
            }

            char first = ToUpper(needle[0]);
            int last = value.Length - needle.Length;

            for (int i = 0; i <= last; i++)
            {
                if (ToUpper(value[i]) != first)
                {
                    continue;
                }

                if (Equals(value.Slice(i, needle.Length), needle, true))
                {
                    return true;
                }
            }

            return false;
        }

        public static bool Equals(ReadOnlySpan<byte> value, ReadOnlySpan<byte> other, bool ignoreCase)
        {
            if (value.Length != other.Length)
            {
                return false;
            }

            if (!ignoreCase)
            {
                return value.SequenceEqual(other);
            }

            for (int i = 0; i < value.Length; i++)
            {
                if (ToUpper(value[i]) != ToUpper(other[i]))
                {
                    return false;
                }
            }

            return true;
        }

        public static bool StartsWith(ReadOnlySpan<byte> value, ReadOnlySpan<byte> prefix, bool ignoreCase)
        {
            return prefix.Length <= value.Length
                && Equals(value.Slice(0, prefix.Length), prefix, ignoreCase);
        }

        public static bool EndsWith(ReadOnlySpan<byte> value, ReadOnlySpan<byte> suffix, bool ignoreCase)
        {
            return suffix.Length <= value.Length
                && Equals(value.Slice(value.Length - suffix.Length), suffix, ignoreCase);
        }

        public static bool Contains(ReadOnlySpan<byte> value, ReadOnlySpan<byte> needle, bool ignoreCase)
        {
            if (needle.Length == 0)
            {
                return true;
            }

            if (needle.Length > value.Length)
            {
                return false;
            }

            if (!ignoreCase)
            {
                return value.IndexOf(needle) >= 0;
            }

            byte first = ToUpper(needle[0]);
            int last = value.Length - needle.Length;

            for (int i = 0; i <= last; i++)
            {
                if (ToUpper(value[i]) != first)
                {
                    continue;
                }

                if (Equals(value.Slice(i, needle.Length), needle, true))
                {
                    return true;
                }
            }

            return false;
        }

        private static char ToUpper(char value)
        {
            if (value >= 'a' && value <= 'z')
            {
                return (char)(value - 32);
            }

            return value < 128 ? value : char.ToUpperInvariant(value);
        }

        private static byte ToUpper(byte value)
        {
            return value >= (byte)'a' && value <= (byte)'z' ? (byte)(value - 32) : value;
        }
    }
}
