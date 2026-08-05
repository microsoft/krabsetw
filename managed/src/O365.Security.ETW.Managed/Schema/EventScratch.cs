using System;
using Microsoft.O365.Security.ETW.Interop;

namespace Microsoft.O365.Security.ETW.Schema
{
    /// <summary>
    /// Per-event mutable state, owned by a trace and reused for every event it delivers.
    /// </summary>
    /// <remarks>
    /// Schema resolution is deferred until something actually reads the payload. Header-only
    /// predicates therefore reject events without ever consulting TDH or the schema cache,
    /// which is the difference between a few nanoseconds and a dictionary lookup for the
    /// events a filter is going to discard anyway.
    ///
    /// One instance per trace, not per provider: ProcessTrace delivers a given trace's events
    /// on a single thread, so no synchronisation is needed, but a provider enabled on two
    /// traces must not share this.
    /// </remarks>
    internal sealed unsafe class EventScratch
    {
        private readonly SchemaCache _cache = new SchemaCache();
        private readonly OffsetResolver _offsets = new OffsetResolver();

        private EVENT_RECORD* _record;
        private SchemaEntry _schema;
        private bool _resolved;

        /// <summary>Begins a new event. Does not resolve the schema.</summary>
        public void Begin(EVENT_RECORD* record)
        {
            _record = record;
            _schema = null;
            _resolved = false;
        }

        public SchemaEntry Schema
        {
            get
            {
                if (!_resolved)
                {
                    Resolve();
                }

                return _schema;
            }
        }

        public OffsetResolver Offsets
        {
            get
            {
                if (!_resolved)
                {
                    Resolve();
                }

                return _offsets;
            }
        }

        /// <summary>Whether the schema has already been fetched for this event.</summary>
        public bool IsResolved
        {
            get { return _resolved; }
        }

        private void Resolve()
        {
            _resolved = true;
            _schema = _cache.Get(_record);

            if (_schema.Table != null)
            {
                _offsets.Begin(_record, _schema);
            }
        }

        /// <summary>Number of TDH lookups performed across this trace's lifetime.</summary>
        internal int SchemaMisses
        {
            get { return _cache.Misses; }
        }

        /// <summary>Exposed for benchmarks that isolate the stages of a lookup.</summary>
        internal SchemaCache Cache
        {
            get { return _cache; }
        }

        public void Dispose()
        {
            _cache.Dispose();
        }
    }
}
