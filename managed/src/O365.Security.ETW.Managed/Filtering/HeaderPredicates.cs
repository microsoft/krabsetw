using System;
using System.Collections.Generic;

namespace O365.Security.ETW
{
    internal sealed class AnyEventPredicate : Predicate
    {
        public static readonly AnyEventPredicate Instance = new AnyEventPredicate();

        private AnyEventPredicate()
        {
        }

        public override PredicateTier Tier
        {
            get { return PredicateTier.Header; }
        }

        public override bool Test(in EventRecordRef record)
        {
            return true;
        }
    }

    internal sealed class NoEventPredicate : Predicate
    {
        public static readonly NoEventPredicate Instance = new NoEventPredicate();

        private NoEventPredicate()
        {
        }

        public override PredicateTier Tier
        {
            get { return PredicateTier.Header; }
        }

        public override bool Test(in EventRecordRef record)
        {
            return false;
        }
    }

    internal sealed class EventIdIsPredicate : Predicate
    {
        private readonly ushort _id;

        public EventIdIsPredicate(ushort id)
        {
            _id = id;
        }

        public override PredicateTier Tier
        {
            get { return PredicateTier.Header; }
        }

        public override bool Test(in EventRecordRef record)
        {
            return record.Id == _id;
        }

        internal override bool TryCollectEventIds(List<ushort> ids)
        {
            ids.Add(_id);
            return true;
        }
    }

    internal sealed class EventOpcodeIsPredicate : Predicate
    {
        private readonly byte _opcode;

        public EventOpcodeIsPredicate(byte opcode)
        {
            _opcode = opcode;
        }

        public override PredicateTier Tier
        {
            get { return PredicateTier.Header; }
        }

        public override bool Test(in EventRecordRef record)
        {
            return record.Opcode == _opcode;
        }
    }

    internal sealed class EventVersionIsPredicate : Predicate
    {
        private readonly byte _version;

        public EventVersionIsPredicate(byte version)
        {
            _version = version;
        }

        public override PredicateTier Tier
        {
            get { return PredicateTier.Header; }
        }

        public override bool Test(in EventRecordRef record)
        {
            return record.Version == _version;
        }
    }

    internal sealed class EventLevelIsPredicate : Predicate
    {
        private readonly byte _level;

        public EventLevelIsPredicate(byte level)
        {
            _level = level;
        }

        public override PredicateTier Tier
        {
            get { return PredicateTier.Header; }
        }

        public override bool Test(in EventRecordRef record)
        {
            return record.Level == _level;
        }
    }

    internal sealed class ProcessIdIsPredicate : Predicate
    {
        private readonly uint _processId;

        public ProcessIdIsPredicate(uint processId)
        {
            _processId = processId;
        }

        public override PredicateTier Tier
        {
            get { return PredicateTier.Header; }
        }

        public override bool Test(in EventRecordRef record)
        {
            return record.ProcessId == _processId;
        }
    }

    internal sealed class ProviderIdIsPredicate : Predicate    {
        private readonly Guid _providerId;

        public ProviderIdIsPredicate(Guid providerId)
        {
            _providerId = providerId;
        }

        public override PredicateTier Tier
        {
            get { return PredicateTier.Header; }
        }

        public override bool Test(in EventRecordRef record)
        {
            return record.ProviderId == _providerId;
        }
    }

    /// <summary>
    /// Wraps a caller-supplied test. Treated as a payload predicate because we cannot know
    /// what it reads.
    /// </summary>
    internal sealed class DelegatePredicate : Predicate
    {
        private readonly EventPredicate _test;

        public DelegatePredicate(EventPredicate test)
        {
            _test = test ?? throw new ArgumentNullException(nameof(test));
        }

        public override bool Test(in EventRecordRef record)
        {
            return _test(record);
        }
    }

    /// <summary>
    /// A caller-supplied event test. Declared as a named delegate because <see cref="Func{T, TResult}"/>
    /// cannot accept a ref struct.
    /// </summary>
    public delegate bool EventPredicate(in EventRecordRef record);
}
