using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace O365.Security.ETW
{
    /// <summary>
    /// An ETW provider to enable on a trace, together with the filters applied to its events.
    /// </summary>
    public sealed class Provider
    {
        private readonly List<EventFilter> _filters = new List<EventFilter>();

        public Provider(Guid id)
        {
            Id = id;
        }

        /// <summary>
        /// Resolves a provider name to its GUID using the algorithm shared by TraceLogging
        /// and EventSource.
        /// </summary>
        public Provider(string name)
        {
            if (string.IsNullOrEmpty(name))
            {
                throw new ArgumentException("A provider name is required.", nameof(name));
            }

            Name = name;
            Id = GuidFromName(name);
        }

        public Guid Id { get; }

        public string Name { get; }

        /// <summary>Events are delivered when any of these keyword bits match.</summary>
        public ulong Any { get; set; }

        /// <summary>Events are delivered only when all of these keyword bits match.</summary>
        public ulong All { get; set; }

        /// <summary>Maximum event level to deliver. Defaults to all levels.</summary>
        public byte Level { get; set; } = 0xFF;

        /// <summary>EVENT_ENABLE_PROPERTY_* flags passed to EnableTraceEx2.</summary>
        public uint TraceFlags { get; set; }

        /// <summary>Invoked for events that no filter claimed. Zero-copy path.</summary>
        public event EventRecordDelegate OnEventSpan;

        /// <summary>Invoked for events that no filter claimed.</summary>
        public event IEventRecordDelegate OnEvent;

        /// <summary>Invoked for events whose schema could not be resolved.</summary>
        public event IEventRecordMetadataDelegate OnMetadata;

        /// <summary>Invoked when a handler throws.</summary>
        public event EventRecordErrorDelegate OnError;

        public void AddFilter(EventFilter filter)
        {
            if (filter == null) throw new ArgumentNullException(nameof(filter));

            _filters.Add(filter);
        }

        internal IReadOnlyList<EventFilter> Filters
        {
            get { return _filters; }
        }

        internal bool HasProviderHandlers
        {
            get { return OnEventSpan != null || OnEvent != null; }
        }

        internal void Dispatch(in EventRecordRef record, EventRecordAdapter adapter)
        {
            for (int i = 0; i < _filters.Count; i++)
            {
                _filters[i].Dispatch(record, adapter);
            }

            var span = OnEventSpan;
            var compat = OnEvent;
            var metadata = OnMetadata;

            if (span == null && compat == null && metadata == null)
            {
                return;
            }

            try
            {
                if (record.HasSchema)
                {
                    span?.Invoke(record);
                    compat?.Invoke(adapter);
                }
                else
                {
                    // No schema, so only header fields are meaningful.
                    metadata?.Invoke(adapter);
                }
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

        /// <summary>
        /// Derives a provider GUID from its name, matching TraceLogging and EventSource:
        /// SHA-1 over a fixed namespace followed by the upper-cased name in big-endian UTF-16,
        /// truncated to 16 bytes and stamped as a version 5 GUID.
        /// </summary>
        internal static Guid GuidFromName(string name)
        {
            byte[] namespaceBytes =
            {
                0x48, 0x2C, 0x2D, 0xB2, 0xC3, 0x90, 0x47, 0xC8,
                0x87, 0xF8, 0x1A, 0x15, 0xBF, 0xC1, 0x30, 0xFB
            };

            string upper = name.ToUpperInvariant();
            var buffer = new byte[namespaceBytes.Length + (upper.Length * 2)];
            Buffer.BlockCopy(namespaceBytes, 0, buffer, 0, namespaceBytes.Length);

            for (int i = 0; i < upper.Length; i++)
            {
                int offset = namespaceBytes.Length + (i * 2);
                buffer[offset] = (byte)(upper[i] >> 8);
                buffer[offset + 1] = (byte)upper[i];
            }

            byte[] hash;
            using (var sha1 = SHA1.Create())
            {
                hash = sha1.ComputeHash(buffer);
            }

            var guidBytes = new byte[16];
            Array.Copy(hash, guidBytes, 16);

            // Stamp the version 5 nibble, exactly as EventSource does. The hash bytes are
            // already laid out the way Guid's byte-array constructor expects, so no field
            // byte swapping is applied.
            guidBytes[7] = (byte)((guidBytes[7] & 0x0F) | 0x50);

            return new Guid(guidBytes);
        }
    }
}
