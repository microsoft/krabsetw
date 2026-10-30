using System;
using System.Collections.Generic;

namespace Microsoft.O365.Security.ETW
{
    /// <summary>
    /// How much of an event a predicate needs before it can decide.
    /// </summary>
    /// <remarks>
    /// Header predicates read only <c>EVENT_HEADER</c>, which is available the instant ETW
    /// hands us the record. Payload predicates need the schema, which costs a TDH lookup on
    /// first sight of an event type and a dictionary probe thereafter. Evaluating header
    /// predicates first lets a filter reject an event before any of that happens.
    /// </remarks>
    public enum PredicateTier
    {
        Header = 0,
        Payload = 1
    }

    /// <summary>
    /// A test applied to an event. Predicates compose into a tree and are evaluated per event,
    /// so implementations must not allocate.
    /// </summary>
    public abstract class Predicate
    {
        /// <summary>Applies the test.</summary>
        public abstract bool Test(in EventRecordRef record);

        /// <summary>What this predicate needs in order to decide.</summary>
        public virtual PredicateTier Tier
        {
            get { return PredicateTier.Payload; }
        }

        /// <summary>
        /// Reports whether this predicate is exactly "the event id is one of these", which
        /// lets the caller push the test into ETW itself.
        /// </summary>
        /// <returns>
        /// True only if matching the collected ids is equivalent to this predicate. A false
        /// return means the predicate must be evaluated in the callback.
        /// </returns>
        internal virtual bool TryCollectEventIds(List<ushort> ids)
        {
            return false;
        }

        public Predicate And(Predicate other)
        {
            return new AndPredicate(this, other);
        }

        public Predicate Or(Predicate other)
        {
            return new OrPredicate(this, other);
        }

        public Predicate Not()
        {
            return new NotPredicate(this);
        }

        /// <summary>
        /// Tests a synthetic record. For testing scenarios only.
        /// </summary>
        /// <remarks>
        /// The record is kept alive across the test: the predicate reads through a raw
        /// pointer taken from it, and a collection in between would otherwise be free to
        /// finalize the record and release the memory being read.
        /// </remarks>
        public unsafe bool Test(Testing.SynthRecord record)
        {
            if (record == null) throw new ArgumentNullException(nameof(record));

            var scratch = new Schema.EventScratch();

            try
            {
                Interop.EVENT_RECORD* raw = record.Record;
                scratch.Begin(raw);
                return Test(new EventRecordRef(raw, scratch));
            }
            finally
            {
                scratch.Dispose();
                GC.KeepAlive(record);
            }
        }

        // C++/CLI emits its instance operator&& / operator|| / operator! as methods with
        // these names, and that is the only way C# can reach them. Kept so test and client
        // code written against the C++/CLI assembly compiles unchanged.
        public Predicate op_LogicalAnd(Predicate other)
        {
            return new AndPredicate(this, other);
        }

        public Predicate op_LogicalOr(Predicate other)
        {
            return new OrPredicate(this, other);
        }

        public Predicate op_LogicalNot()
        {
            return new NotPredicate(this);
        }

        public static Predicate operator &(Predicate left, Predicate right)
        {
            return new AndPredicate(left, right);
        }

        public static Predicate operator |(Predicate left, Predicate right)
        {
            return new OrPredicate(left, right);
        }

        public static Predicate operator !(Predicate value)
        {
            return new NotPredicate(value);
        }

        // Present so that `a && b` and `a || b` resolve to the short-circuiting forms of the
        // & and | operators above, matching how the C++/CLI API reads at the call site.
        public static bool operator true(Predicate value)
        {
            return false;
        }

        public static bool operator false(Predicate value)
        {
            return false;
        }
    }

    internal sealed class AndPredicate : Predicate
    {
        private readonly Predicate _first;
        private readonly Predicate _second;
        private readonly PredicateTier _tier;

        public AndPredicate(Predicate left, Predicate right)
        {
            if (left == null) throw new ArgumentNullException(nameof(left));
            if (right == null) throw new ArgumentNullException(nameof(right));

            // Cheapest side first. Ordering is decided once, here, not per event.
            if (left.Tier <= right.Tier)
            {
                _first = left;
                _second = right;
            }
            else
            {
                _first = right;
                _second = left;
            }

            _tier = _first.Tier < _second.Tier ? _second.Tier : _first.Tier;
        }

        public override PredicateTier Tier
        {
            get { return _tier; }
        }

        public override bool Test(in EventRecordRef record)
        {
            return _first.Test(record) && _second.Test(record);
        }
    }

    internal sealed class OrPredicate : Predicate
    {
        private readonly Predicate _first;
        private readonly Predicate _second;
        private readonly PredicateTier _tier;

        public OrPredicate(Predicate left, Predicate right)
        {
            if (left == null) throw new ArgumentNullException(nameof(left));
            if (right == null) throw new ArgumentNullException(nameof(right));

            if (left.Tier <= right.Tier)
            {
                _first = left;
                _second = right;
            }
            else
            {
                _first = right;
                _second = left;
            }

            _tier = _first.Tier < _second.Tier ? _second.Tier : _first.Tier;
        }

        public override PredicateTier Tier
        {
            get { return _tier; }
        }

        public override bool Test(in EventRecordRef record)
        {
            return _first.Test(record) || _second.Test(record);
        }

        internal override bool TryCollectEventIds(List<ushort> ids)
        {
            // A union of id sets is still an id set.
            return _first.TryCollectEventIds(ids) && _second.TryCollectEventIds(ids);
        }
    }

    internal sealed class NotPredicate : Predicate
    {
        private readonly Predicate _inner;

        public NotPredicate(Predicate inner)
        {
            _inner = inner ?? throw new ArgumentNullException(nameof(inner));
        }

        public override PredicateTier Tier
        {
            get { return _inner.Tier; }
        }

        public override bool Test(in EventRecordRef record)
        {
            return !_inner.Test(record);
        }
    }
}
