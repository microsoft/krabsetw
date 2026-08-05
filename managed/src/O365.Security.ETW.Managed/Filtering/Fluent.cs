using System;

namespace O365.Security.ETW
{
    /// <summary>
    /// Factory methods for event predicates. Mirrors the C++/CLI <c>Filter</c> class.
    /// </summary>
    public static class Filter
    {
        public static Predicate AnyEvent()
        {
            return AnyEventPredicate.Instance;
        }

        public static Predicate NoEvent()
        {
            return NoEventPredicate.Instance;
        }

        public static Predicate Not(Predicate other)
        {
            return new NotPredicate(other);
        }

        public static Predicate EventIdIs(int id)
        {
            return new EventIdIsPredicate(checked((ushort)id));
        }

        public static Predicate EventOpcodeIs(int opcode)
        {
            return new EventOpcodeIsPredicate(checked((byte)opcode));
        }

        public static Predicate EventVersionIs(int version)
        {
            return new EventVersionIsPredicate(checked((byte)version));
        }

        public static Predicate EventLevelIs(int level)
        {
            return new EventLevelIsPredicate(checked((byte)level));
        }

        public static Predicate ProcessIdIs(int processId)
        {
            return new ProcessIdIsPredicate(unchecked((uint)processId));
        }

        public static Predicate ProviderIdIs(Guid providerId)
        {
            return new ProviderIdIsPredicate(providerId);
        }

        /// <summary>
        /// Matches the schema event name. Use for TraceLogging providers, where every event
        /// carries id zero.
        /// </summary>
        public static Predicate EventNameIs(string name)
        {
            return new EventNameIsPredicate(name, false);
        }

        public static Predicate EventNameIEquals(string name)
        {
            return new EventNameIsPredicate(name, true);
        }

        public static Predicate IsUInt32(string propertyName, uint value)
        {
            return new UInt32PropertyPredicate(propertyName, value);
        }

        public static Predicate IsUInt64(string propertyName, ulong value)
        {
            return new UInt64PropertyPredicate(propertyName, value);
        }

        /// <summary>Wraps a caller-supplied test.</summary>
        public static Predicate Custom(EventPredicate test)
        {
            return new DelegatePredicate(test);
        }
    }

    /// <summary>Predicates over UTF-16 string properties.</summary>
    public static class UnicodeString
    {
        public static Predicate Is(string name, string value)
        {
            return new UnicodeStringPredicate(name, value, StringMatch.Equals, false);
        }

        public static Predicate IEquals(string name, string value)
        {
            return new UnicodeStringPredicate(name, value, StringMatch.Equals, true);
        }

        public static Predicate Contains(string name, string value)
        {
            return new UnicodeStringPredicate(name, value, StringMatch.Contains, false);
        }

        public static Predicate IContains(string name, string value)
        {
            return new UnicodeStringPredicate(name, value, StringMatch.Contains, true);
        }

        public static Predicate StartsWith(string name, string value)
        {
            return new UnicodeStringPredicate(name, value, StringMatch.StartsWith, false);
        }

        public static Predicate IStartsWith(string name, string value)
        {
            return new UnicodeStringPredicate(name, value, StringMatch.StartsWith, true);
        }

        public static Predicate EndsWith(string name, string value)
        {
            return new UnicodeStringPredicate(name, value, StringMatch.EndsWith, false);
        }

        public static Predicate IEndsWith(string name, string value)
        {
            return new UnicodeStringPredicate(name, value, StringMatch.EndsWith, true);
        }
    }

    /// <summary>
    /// Predicates over counted string properties.
    /// </summary>
    /// <remarks>
    /// Decoding is driven by the property's TDH in-type, so these behave identically to
    /// <see cref="UnicodeString"/>. The type is kept for source compatibility.
    /// </remarks>
    public static class CountedString
    {
        public static Predicate Is(string name, string value)
        {
            return UnicodeString.Is(name, value);
        }

        public static Predicate IEquals(string name, string value)
        {
            return UnicodeString.IEquals(name, value);
        }

        public static Predicate Contains(string name, string value)
        {
            return UnicodeString.Contains(name, value);
        }

        public static Predicate IContains(string name, string value)
        {
            return UnicodeString.IContains(name, value);
        }

        public static Predicate StartsWith(string name, string value)
        {
            return UnicodeString.StartsWith(name, value);
        }

        public static Predicate IStartsWith(string name, string value)
        {
            return UnicodeString.IStartsWith(name, value);
        }

        public static Predicate EndsWith(string name, string value)
        {
            return UnicodeString.EndsWith(name, value);
        }

        public static Predicate IEndsWith(string name, string value)
        {
            return UnicodeString.IEndsWith(name, value);
        }
    }

    /// <summary>Predicates over 8-bit string properties.</summary>
    public static class AnsiString
    {
        public static Predicate Is(string name, string value)
        {
            return new AnsiStringPredicate(name, value, StringMatch.Equals, false);
        }

        public static Predicate IEquals(string name, string value)
        {
            return new AnsiStringPredicate(name, value, StringMatch.Equals, true);
        }

        public static Predicate Contains(string name, string value)
        {
            return new AnsiStringPredicate(name, value, StringMatch.Contains, false);
        }

        public static Predicate IContains(string name, string value)
        {
            return new AnsiStringPredicate(name, value, StringMatch.Contains, true);
        }

        public static Predicate StartsWith(string name, string value)
        {
            return new AnsiStringPredicate(name, value, StringMatch.StartsWith, false);
        }

        public static Predicate IStartsWith(string name, string value)
        {
            return new AnsiStringPredicate(name, value, StringMatch.StartsWith, true);
        }

        public static Predicate EndsWith(string name, string value)
        {
            return new AnsiStringPredicate(name, value, StringMatch.EndsWith, false);
        }

        public static Predicate IEndsWith(string name, string value)
        {
            return new AnsiStringPredicate(name, value, StringMatch.EndsWith, true);
        }
    }
}
