using System;

namespace Microsoft.O365.Security.ETW
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
    /// Predicates over counted string properties: a UINT16 byte count followed by UTF-16
    /// character data.
    /// </summary>
    /// <remarks>
    /// The counted layout is forced rather than inferred from the property's TDH in-type,
    /// matching native krabs. Classic WBEM schemas frequently declare such a field as a plain
    /// UNICODESTRING, and inferring would leave the count bytes inside the compared value.
    /// </remarks>
    public static class CountedString
    {
        public static Predicate Is(string name, string value)
        {
            return new CountedStringPredicate(name, value, StringMatch.Equals, false);
        }

        public static Predicate IEquals(string name, string value)
        {
            return new CountedStringPredicate(name, value, StringMatch.Equals, true);
        }

        public static Predicate Contains(string name, string value)
        {
            return new CountedStringPredicate(name, value, StringMatch.Contains, false);
        }

        public static Predicate IContains(string name, string value)
        {
            return new CountedStringPredicate(name, value, StringMatch.Contains, true);
        }

        public static Predicate StartsWith(string name, string value)
        {
            return new CountedStringPredicate(name, value, StringMatch.StartsWith, false);
        }

        public static Predicate IStartsWith(string name, string value)
        {
            return new CountedStringPredicate(name, value, StringMatch.StartsWith, true);
        }

        public static Predicate EndsWith(string name, string value)
        {
            return new CountedStringPredicate(name, value, StringMatch.EndsWith, false);
        }

        public static Predicate IEndsWith(string name, string value)
        {
            return new CountedStringPredicate(name, value, StringMatch.EndsWith, true);
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
