using System;

namespace Microsoft.O365.Security.ETW
{
    /// <summary>
    /// Represents a raw user trace provider and its configuration. Emits
    /// <see cref="IEventRecordMetadata"/> instead of <see cref="IEventRecord"/>, so it can
    /// deliver events that have no registered schema.
    /// </summary>
    [Obsolete("This class is deprecated. Use the Provider.OnMetadata event instead.")]
    public sealed class RawProvider
    {
        private readonly Provider _provider;

        /// <summary>A bitmask with all bits set, to catch every event.</summary>
        public const ulong AllBitsSet = ulong.MaxValue;

        public RawProvider(Guid id)
        {
            _provider = new Provider(id);
        }

        public RawProvider(string providerName)
        {
            _provider = new Provider(providerName);
        }

        public ulong Any
        {
            set { _provider.Any = value; }
        }

        public ulong All
        {
            set { _provider.All = value; }
        }

        public byte Level
        {
            set { _provider.Level = value; }
        }

        public TraceFlags TraceFlags
        {
            get { return _provider.TraceFlags; }
            set { _provider.TraceFlags = value; }
        }

        /// <summary>
        /// Fired for every event, before any schema is resolved. Named OnEvent for
        /// compatibility, but it carries metadata only.
        /// </summary>
        public event IEventRecordMetadataDelegate OnEvent
        {
            add { _provider.OnMetadata += value; }
            remove { _provider.OnMetadata -= value; }
        }

        internal Provider Underlying
        {
            get { return _provider; }
        }
    }
}
