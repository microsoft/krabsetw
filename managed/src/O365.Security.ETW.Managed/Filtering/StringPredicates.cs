using System;
using System.Text;
using Microsoft.O365.Security.ETW.Interop;

namespace Microsoft.O365.Security.ETW
{
    internal enum StringMatch
    {
        Equals,
        Contains,
        StartsWith,
        EndsWith
    }

    /// <summary>
    /// Compares a UTF-16 string property against a fixed value without materialising a
    /// <see cref="string"/> for the event data.
    /// </summary>
    /// <remarks>
    /// Also serves counted strings: the leading length prefix is stripped during decoding,
    /// which is driven by the property's TDH in-type rather than by the predicate.
    /// </remarks>
    internal sealed class UnicodeStringPredicate : Predicate
    {
        private readonly string _name;
        private readonly string _value;
        private readonly StringMatch _match;
        private readonly bool _ignoreCase;

        public UnicodeStringPredicate(string name, string value, StringMatch match, bool ignoreCase)
        {
            _name = name ?? throw new ArgumentNullException(nameof(name));
            _value = value ?? throw new ArgumentNullException(nameof(value));
            _match = match;
            _ignoreCase = ignoreCase;
        }

        public override bool Test(in EventRecordRef record)
        {
            if (!record.TryGetUnicodeString(_name.AsSpan(), out ReadOnlySpan<char> actual))
            {
                return false;
            }

            ReadOnlySpan<char> expected = _value.AsSpan();

            switch (_match)
            {
                case StringMatch.Equals:
                    return SpanCompare.Equals(actual, expected, _ignoreCase);
                case StringMatch.Contains:
                    return SpanCompare.Contains(actual, expected, _ignoreCase);
                case StringMatch.StartsWith:
                    return SpanCompare.StartsWith(actual, expected, _ignoreCase);
                case StringMatch.EndsWith:
                    return SpanCompare.EndsWith(actual, expected, _ignoreCase);
                default:
                    return false;
            }
        }
    }

    /// <summary>
    /// Compares a counted UTF-16 string property against a fixed value.
    /// </summary>
    /// <remarks>
    /// Forces the counted interpretation regardless of the property's TDH in-type, which is
    /// what krabs::predicates::adapters::counted_string does.
    /// </remarks>
    internal sealed class CountedStringPredicate : Predicate
    {
        private readonly string _name;
        private readonly string _value;
        private readonly StringMatch _match;
        private readonly bool _ignoreCase;

        public CountedStringPredicate(string name, string value, StringMatch match, bool ignoreCase)
        {
            _name = name ?? throw new ArgumentNullException(nameof(name));
            _value = value ?? throw new ArgumentNullException(nameof(value));
            _match = match;
            _ignoreCase = ignoreCase;
        }

        public override bool Test(in EventRecordRef record)
        {
            if (!record.TryGetCountedString(_name.AsSpan(), out ReadOnlySpan<char> actual))
            {
                return false;
            }

            ReadOnlySpan<char> expected = _value.AsSpan();

            switch (_match)
            {
                case StringMatch.Equals:
                    return SpanCompare.Equals(actual, expected, _ignoreCase);
                case StringMatch.Contains:
                    return SpanCompare.Contains(actual, expected, _ignoreCase);
                case StringMatch.StartsWith:
                    return SpanCompare.StartsWith(actual, expected, _ignoreCase);
                case StringMatch.EndsWith:
                    return SpanCompare.EndsWith(actual, expected, _ignoreCase);
                default:
                    return false;
            }
        }
    }

    /// <summary>
    /// Compares an 8-bit string property against a fixed value. The comparison value is
    /// transcoded once at construction, so matching is a byte compare against the payload.
    /// </summary>
    internal sealed class AnsiStringPredicate : Predicate
    {
        private readonly string _name;
        private readonly byte[] _value;
        private readonly StringMatch _match;
        private readonly bool _ignoreCase;

        public AnsiStringPredicate(string name, string value, StringMatch match, bool ignoreCase)
        {
            if (value == null) throw new ArgumentNullException(nameof(value));

            _name = name ?? throw new ArgumentNullException(nameof(name));

            // The ANSI code page, matching how these properties are decoded and how the
            // C++/CLI wrapper marshals the value it compares against
            // (msclr::interop::marshal_as<std::string>, which is also CP_ACP).
            _value = AnsiEncoding.Current.GetBytes(value);
            _match = match;
            _ignoreCase = ignoreCase;
        }

        public override bool Test(in EventRecordRef record)
        {
            if (!record.TryGetAnsiStringBytes(_name.AsSpan(), out ReadOnlySpan<byte> actual))
            {
                return false;
            }

            var expected = new ReadOnlySpan<byte>(_value);

            switch (_match)
            {
                case StringMatch.Equals:
                    return SpanCompare.Equals(actual, expected, _ignoreCase);
                case StringMatch.Contains:
                    return SpanCompare.Contains(actual, expected, _ignoreCase);
                case StringMatch.StartsWith:
                    return SpanCompare.StartsWith(actual, expected, _ignoreCase);
                case StringMatch.EndsWith:
                    return SpanCompare.EndsWith(actual, expected, _ignoreCase);
                default:
                    return false;
            }
        }
    }

    /// <summary>
    /// Matches on the schema event name. Needed for TraceLogging providers, whose events all
    /// carry event id zero and are distinguished by name.
    /// </summary>
    internal sealed class EventNameIsPredicate : Predicate
    {
        private readonly string _name;
        private readonly bool _ignoreCase;

        public EventNameIsPredicate(string name, bool ignoreCase)
        {
            _name = name ?? throw new ArgumentNullException(nameof(name));
            _ignoreCase = ignoreCase;
        }

        public override bool Test(in EventRecordRef record)
        {
            return SpanCompare.Equals(record.Name, _name.AsSpan(), _ignoreCase);
        }
    }

    internal sealed class UInt32PropertyPredicate : Predicate    {
        private readonly string _name;
        private readonly uint _value;

        public UInt32PropertyPredicate(string name, uint value)
        {
            _name = name ?? throw new ArgumentNullException(nameof(name));
            _value = value;
        }

        public override bool Test(in EventRecordRef record)
        {
            return record.TryGetUInt32(_name.AsSpan(), out uint actual) && actual == _value;
        }
    }

    internal sealed class UInt64PropertyPredicate : Predicate
    {
        private readonly string _name;
        private readonly ulong _value;

        public UInt64PropertyPredicate(string name, ulong value)
        {
            _name = name ?? throw new ArgumentNullException(nameof(name));
            _value = value;
        }

        public override bool Test(in EventRecordRef record)
        {
            return record.TryGetUInt64(_name.AsSpan(), out ulong actual) && actual == _value;
        }
    }
}
