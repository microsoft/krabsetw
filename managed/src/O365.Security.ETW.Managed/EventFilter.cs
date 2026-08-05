using System;
using System.Collections.Generic;
using O365.Security.ETW.Interop;

namespace O365.Security.ETW
{
    /// <summary>
    /// Filters events before they reach a handler, and where possible before they reach the
    /// process at all.
    /// </summary>
    /// <remarks>
    /// Event ids supplied here, or derivable from the predicate, are pushed into ETW via
    /// EnableTraceEx2. Non-matching events are then never written to the session buffers,
    /// which is far cheaper than discarding them in the callback.
    /// </remarks>
    public sealed class EventFilter
    {
        private readonly List<ushort> _eventIds;

        public EventFilter(Predicate predicate)
        {
            Predicate = predicate ?? throw new ArgumentNullException(nameof(predicate));
            _eventIds = DeriveEventIds(predicate);
        }

        public EventFilter(ushort eventId)
            : this(eventId, AnyEventPredicate.Instance)
        {
        }

        public EventFilter(ushort eventId, Predicate predicate)
        {
            Predicate = predicate ?? throw new ArgumentNullException(nameof(predicate));
            _eventIds = new List<ushort> { eventId };
        }

        public EventFilter(List<ushort> eventIds)
            : this(eventIds, AnyEventPredicate.Instance)
        {
        }

        public EventFilter(List<ushort> eventIds, Predicate predicate)
        {
            if (eventIds == null) throw new ArgumentNullException(nameof(eventIds));
            if (eventIds.Count == 0) throw new ArgumentException("At least one event id is required.", nameof(eventIds));

            Predicate = predicate ?? throw new ArgumentNullException(nameof(predicate));
            _eventIds = new List<ushort>(eventIds);
        }

        internal Predicate Predicate { get; }

        /// <summary>Invoked for each event that satisfies the predicate. Zero-copy path.</summary>
        public event EventRecordDelegate OnEventSpan;

        /// <summary>Invoked for each event that satisfies the predicate.</summary>
        public event IEventRecordDelegate OnEvent;

        /// <summary>Invoked when a handler throws.</summary>
        public event EventRecordErrorDelegate OnError;

        internal bool HasHandlers
        {
            get { return OnEventSpan != null || OnEvent != null; }
        }

        /// <summary>
        /// Event ids that can be pushed into ETW, or null when the filter cannot be reduced
        /// to a bounded id set.
        /// </summary>
        internal IReadOnlyList<ushort> EventIds
        {
            get { return _eventIds; }
        }

        private static List<ushort> DeriveEventIds(Predicate predicate)
        {
            var ids = new List<ushort>();

            if (!predicate.TryCollectEventIds(ids) || ids.Count == 0)
            {
                return null;
            }

            // ETW caps how many ids a single filter can carry. Beyond that, fall back to
            // testing in the callback rather than silently dropping ids.
            return ids.Count > NativeConstants.MAX_EVENT_FILTER_EVENT_ID_COUNT ? null : ids;
        }

        internal unsafe void Dispatch(in EventRecordRef record, EventRecordAdapter adapter)
        {
            if (!Predicate.Test(record))
            {
                return;
            }

            var span = OnEventSpan;
            var compat = OnEvent;

            try
            {
                span?.Invoke(record);
                compat?.Invoke(adapter);
            }
            catch (Exception ex)
            {
                var handler = OnError;
                if (handler == null)
                {
                    throw;
                }

                handler(new EventRecordError(ex.Message, adapter));
            }
        }
    }
}
