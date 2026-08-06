using System;
using System.Collections.Generic;
using Microsoft.O365.Security.ETW.Interop;
using Microsoft.O365.Security.ETW.Schema;

namespace Microsoft.O365.Security.ETW
{
    /// <summary>
    /// Represents a kernel trace provider and its configuration.
    /// </summary>
    public class KernelProvider
    {
        private readonly List<EventFilter> _filters = new List<EventFilter>();

        /// <summary>
        /// Constructs a KernelProvider identified by its GUID and enabled by a trace flag.
        /// </summary>
        /// <param name="flags">the EVENT_TRACE_FLAG_* value that enables this provider</param>
        /// <param name="id">the GUID the kernel logger stamps on this provider's events</param>
        public KernelProvider(uint flags, Guid id)
        {
            Flags = flags;
            Id = id;
        }

        /// <summary>
        /// Constructs a KernelProvider identified by its GUID and enabled by a group mask.
        /// </summary>
        /// <remarks>Only supported on Windows 8 and newer.</remarks>
        public KernelProvider(Guid id, uint mask)
        {
            Id = id;
            GroupMask = mask;
        }

        /// <summary>The GUID associated with this provider.</summary>
        public Guid Id { get; }

        /// <summary>The EVENT_TRACE_FLAG_* value OR'd into the session's EnableFlags.</summary>
        public uint Flags { get; }

        /// <summary>The PERFINFO group mask OR'd into the session's group mask.</summary>
        /// <remarks>
        /// Native PERFINFO_MASK is a ULONG, so this is 32 bits wide. A wider type would let
        /// callers pass bits that <see cref="KernelTrace"/> silently discards.
        /// </remarks>
        public uint GroupMask { get; }

        /// <summary>Fired for every event, before any schema is resolved.</summary>
        public event IEventRecordMetadataDelegate OnMetadata;

        /// <summary>Fired for every event whose schema could be resolved.</summary>
        public event IEventRecordDelegate OnEvent;

        /// <summary>
        /// Zero-allocation counterpart to <see cref="OnEvent"/>. Not gated on a schema.
        /// </summary>
        public event EventRecordDelegate OnEventSpan;

        /// <summary>Fired when an event arrives but cannot be handled.</summary>
        public event EventRecordErrorDelegate OnError;

        /// <summary>Adds a filter to the provider.</summary>
        public void AddFilter(EventFilter filter)
        {
            if (filter == null) throw new ArgumentNullException(nameof(filter));

            _filters.Add(filter);
        }

        internal void Dispatch(in EventRecordRef record, EventRecordAdapter adapter)
        {
            // Same order as Provider.Dispatch, which is the order krabs' shared
            // base_provider::on_event uses for both provider kinds.
            OnMetadata?.Invoke(adapter);

            var span = OnEventSpan;
            var compat = OnEvent;

            if (span != null || compat != null)
            {
                span?.Invoke(record);

                if (compat != null)
                {
                    SchemaEntry schema = record.SchemaEntry;

                    if (schema.Status != NativeConstants.ERROR_SUCCESS)
                    {
                        var onError = OnError;
                        onError?.Invoke(new EventRecordError(
                            ErrorMessages.StatusAndRecordContext(
                                schema.Status, record.ProviderId, record.Id),
                            adapter));
                    }
                    else
                    {
                        compat(adapter);
                    }
                }
            }

            for (int i = 0; i < _filters.Count; i++)
            {
                _filters[i].Dispatch(record, adapter);
            }
        }
    }
}
