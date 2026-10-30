using System;
using System.Collections.Generic;
using Microsoft.O365.Security.ETW.Interop;
using Microsoft.O365.Security.ETW.Schema;

namespace Microsoft.O365.Security.ETW
{
    /// <summary>
    /// Filters events before they reach a handler, and where possible before they reach the
    /// process at all.
    /// </summary>
    /// <remarks>
    /// Event ids supplied here, or derivable from the predicate, are pushed into ETW via
    /// EnableTraceEx2. Non-matching events are then never written to the session buffers,
    /// which is far cheaper than discarding them in the callback.
    ///
    /// Pushdown is only ever an optimisation: the ids are re-tested here on every event, so
    /// a filter behaves identically whether or not ETW honoured the request. Native krabs
    /// relies on the pushdown alone, which silently misbehaves for the providers and event
    /// types that ETW does not apply id filtering to.
    /// </remarks>
    public sealed class EventFilter
    {
        private readonly ushort[]? _eventIds;
        private readonly List<ushort>? _pushdownIds;

        public EventFilter(Predicate predicate)
        {
            Predicate = predicate ?? throw new ArgumentNullException(nameof(predicate));
            _eventIds = null;
            _pushdownIds = DeriveEventIds(predicate);
        }

        public EventFilter(ushort eventId)
            : this(eventId, null)
        {
        }

        public EventFilter(ushort eventId, Predicate? predicate)
        {
            Predicate = predicate;
            _eventIds = new[] { eventId };
            _pushdownIds = new List<ushort> { eventId };
        }

        public EventFilter(List<ushort> eventIds)
            : this(eventIds, null)
        {
        }

        public EventFilter(List<ushort> eventIds, Predicate? predicate)
        {
            if (eventIds == null) throw new ArgumentNullException(nameof(eventIds));
            if (eventIds.Count == 0) throw new ArgumentException("At least one event id is required.", nameof(eventIds));

            Predicate = predicate;
            _eventIds = eventIds.ToArray();
            _pushdownIds = new List<ushort>(eventIds);
        }

        internal Predicate? Predicate { get; }

        /// <summary>
        /// Invoked for each event that satisfies the filter, allocating nothing.
        /// </summary>
        /// <inheritdoc cref="Provider.OnEventRef" path="/remarks"/>
        public event EventRecordDelegate? OnEventRef;

        /// <summary>Invoked for each event that satisfies the filter.</summary>
        public event IEventRecordDelegate? OnEvent;

        /// <summary>
        /// Invoked when an event's schema could not be resolved. Reached only when the filter
        /// is driven directly, as <c>Proxy(EventFilter)</c> does: a filter reached through a
        /// provider is only ever offered an event whose schema already resolved, because
        /// <see cref="Provider.Dispatch"/> reports the failure through
        /// <see cref="Provider.OnError"/> and skips its filters.
        /// </summary>
        public event EventRecordErrorDelegate? OnError;

        internal bool HasHandlers
        {
            get { return OnEventRef != null || OnEvent != null; }
        }

        /// <summary>
        /// Event ids that can be pushed into ETW, or null when the filter cannot be reduced
        /// to a bounded id set.
        /// </summary>
        internal IReadOnlyList<ushort>? EventIds
        {
            get { return _pushdownIds; }
        }

        private static List<ushort>? DeriveEventIds(Predicate predicate)
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

        private bool MatchesEventId(ushort id)
        {
            ushort[]? ids = _eventIds;
            if (ids == null)
            {
                return true;
            }

            for (int i = 0; i < ids.Length; i++)
            {
                if (ids[i] == id)
                {
                    return true;
                }
            }

            return false;
        }

        internal void Dispatch(in EventRecordRef record, EventRecordAdapter adapter)
        {
            if (!MatchesEventId(record.Id))
            {
                return;
            }

            // Provider.Dispatch resolves the schema and reports a failure once through
            // Provider.OnError before reaching any filter, so on that path this gate always
            // passes -- the cost is one cached status read. It earns its keep when a filter
            // is driven directly rather than through a provider, as Proxy(EventFilter) does,
            // where nothing above the filter can resolve or report.
            Predicate? predicate = Predicate;

            if (predicate != null && !predicate.Test(record))
            {
                return;
            }

            if (!EnsureSchema(record, adapter))
            {
                return;
            }

            OnEventRef?.Invoke(record);
            OnEvent?.Invoke(adapter);
        }

        /// <summary>
        /// Resolves the schema, reporting a failure to <see cref="OnError"/>.
        /// </summary>
        /// <returns>True when the schema is available.</returns>
        private bool EnsureSchema(in EventRecordRef record, EventRecordAdapter adapter)
        {
            SchemaEntry schema = record.SchemaEntry;

            if (schema.Status == NativeConstants.ERROR_SUCCESS)
            {
                return true;
            }

            var handler = OnError;
            handler?.Invoke(new EventRecordError(
                ErrorMessages.StatusAndRecordContext(schema.Status, record.ProviderId, record.Id),
                adapter));

            return false;
        }
    }
}
