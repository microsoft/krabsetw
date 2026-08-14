using System;
using System.Collections.Generic;
using Microsoft.O365.Security.ETW.Interop;
using Microsoft.O365.Security.ETW.Schema;

namespace Microsoft.O365.Security.ETW
{
    /// <summary>
    /// EVENT_ENABLE_PROPERTY_* values passed to EnableTraceEx2.
    /// </summary>
    [Flags]
    public enum TraceFlags : uint
    {
        None = 0x00000000,

        /// <summary>User SID for the event is included in the ExtendedData field.</summary>
        IncludeUserSid = 0x00000001,

        /// <summary>Terminal Session ID for the event is included in the ExtendedData field.</summary>
        IncludeTerminalSessionId = 0x00000002,

        /// <summary>Stack trace for the event is included in the ExtendedData field.</summary>
        IncludeStackTrace = 0x00000004,

        /// <summary>Filters out all events that do not have a non-zero keyword specified.</summary>
        IgnoreKeyword0 = 0x00000010,

        /// <summary>Enable a provider group rather than an individual provider.</summary>
        EnableProviderGroup = 0x00000020,

        /// <summary>Include the Process Start Key in the extended data.</summary>
        IncludeProcessStartKey = 0x00000080,

        /// <summary>Include the Event Key in the extended data.</summary>
        IncludeProcessEventKey = 0x00000100,

        /// <summary>Filters out events marked InPrivate, or from processes marked InPrivate.</summary>
        ExcludeInPrivateEventKey = 0x00000200,

        /// <summary>Receive events from processes running inside Windows containers.</summary>
        EnableSilosEventKey = 0x00000400,

        /// <summary>Include the container ID in the ExtendedData field.</summary>
        SourceContainerTrackingEventKey = 0x00000800
    }

    /// <summary>
    /// An ETW provider to enable on a trace, together with the filters applied to its events.
    /// </summary>
    public sealed class Provider : IDisposable
    {
        /// <summary>A keyword mask with every bit set.</summary>
        public const ulong AllBitsSet = ulong.MaxValue;

        private readonly List<EventFilter> _filters = new List<EventFilter>();

        public Provider(Guid id)
        {
            Id = id;
        }

        /// <summary>
        /// Resolves a provider name to its GUID by asking TDH for the registered providers.
        /// </summary>
        /// <exception cref="ArgumentException">The name is not a registered provider.</exception>
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

        /// <summary>
        /// The provider name, when the provider was constructed from one. Null when it was
        /// constructed from a GUID, because nothing resolves a GUID back to a name.
        /// </summary>
        public string? Name { get; }

        /// <summary>Events are delivered when any of these keyword bits match.</summary>
        public ulong Any { get; set; }

        /// <summary>Events are delivered only when all of these keyword bits match.</summary>
        public ulong All { get; set; }

        /// <summary>
        /// Maximum event level to deliver. Defaults to 5 (verbose), matching native krabs.
        /// </summary>
        public byte Level { get; set; } = 5;

        /// <summary>EVENT_ENABLE_PROPERTY_* flags passed to EnableTraceEx2.</summary>
        public TraceFlags TraceFlags { get; set; }

        /// <summary>Whether the provider is asked to log its state on enable.</summary>
        public bool RundownEnabled { get; private set; }

        /// <summary>
        /// Invoked for every event delivered to this provider, allocating nothing.
        /// </summary>
        /// <remarks>
        /// The record is an <see cref="EventRecordRef"/>, a ref struct that views the payload
        /// in place, so the handler must be written with an explicit parameter type
        /// (<c>(in EventRecordRef record) =&gt; ...</c>). An implicitly typed lambda cannot
        /// bind here, because a lambda cannot infer the <c>in</c> modifier.
        ///
        /// The record is only valid for the duration of the call. Anything kept past the
        /// handler must be copied out first.
        /// </remarks>
        public event EventRecordDelegate? OnEventRef;

        /// <summary>Invoked for every event delivered to this provider.</summary>
        public event IEventRecordDelegate? OnEvent;

        /// <summary>
        /// Invoked for every event delivered to this provider, before any schema is resolved.
        /// </summary>
        /// <remarks>
        /// Fires unconditionally and first, matching the native CallbackBridge. Handlers see
        /// header fields only; touching a payload accessor would force a schema lookup and
        /// defeat the point of the callback.
        /// </remarks>
        public event IEventRecordMetadataDelegate? OnMetadata;

        /// <summary>Invoked when an event's schema could not be resolved.</summary>
        public event EventRecordErrorDelegate? OnError;

        /// <summary>
        /// Requests that the provider log its state information when enabled.
        /// </summary>
        public void EnableRundownEvents()
        {
            RundownEnabled = true;
        }

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
            get { return OnEventRef != null || OnEvent != null || OnMetadata != null; }
        }

        internal void Dispatch(in EventRecordRef record, EventRecordAdapter adapter)
        {
            // Order matches krabs::details::base_provider::on_event: the provider's own
            // callbacks run before its filters, and within the callback bridge OnMetadata
            // runs before OnEvent.
            OnMetadata?.Invoke(adapter);

            var handler = OnEventRef;
            var compat = OnEvent;

            if (handler == null && compat == null && _filters.Count == 0)
            {
                return;
            }

            // Every remaining surface is gated on a schema. Neither event surface can do
            // anything useful without one: IEventRecord exposes TaskName, Properties and
            // friends as plain properties with no failure channel, and EventRecordRef can
            // only reach the header and the undecoded UserDataSpan. Filters cannot evaluate
            // a payload predicate without one either. A consumer that wants the event
            // regardless of decodability wants OnMetadata, which fires above and is not
            // gated.
            //
            // Resolving here rather than in each filter is a deliberate divergence. Native
            // lets the schema constructor throw out of each predicate (krabs
            // filtering/predicates.hpp:134) into that filter's own try/catch
            // (filtering/event_filter.hpp:214), so an undecodable event raises one error per
            // filter, on a surface consumers rarely subscribe -- Provider.OnError never sees
            // it at all for a filtered provider. Reporting it once, on the provider, matches
            // where consumers actually attach their error handling.
            SchemaEntry schema = record.SchemaEntry;

            if (schema.Status != NativeConstants.ERROR_SUCCESS)
            {
                RaiseError(schema.Status, record, adapter);
                return;
            }

            handler?.Invoke(record);
            compat?.Invoke(adapter);

            for (int i = 0; i < _filters.Count; i++)
            {
                _filters[i].Dispatch(record, adapter);
            }
        }

        private void RaiseError(int status, in EventRecordRef record, EventRecordAdapter adapter)
        {
            var handler = OnError;
            if (handler == null)
            {
                return;
            }

            handler(new EventRecordError(
                ErrorMessages.StatusAndRecordContext(status, record.ProviderId, record.Id),
                adapter));
        }

        /// <summary>
        /// Resolves a provider name to its GUID via TdhEnumerateProviders, matching
        /// krabs::provider::provider_name_to_guid.
        /// </summary>
        /// <remarks>
        /// Deliberately not the EventSource/TraceLogging name hash: that would happily
        /// produce a GUID for a provider that does not exist, and the resulting session
        /// would silently receive nothing.
        /// </remarks>
        internal static unsafe Guid GuidFromName(string name)
        {
            uint size = 0;
            int status = NativeMethods.TdhEnumerateProviders(null, &size);

            if (status != NativeConstants.ERROR_INSUFFICIENT_BUFFER)
            {
                throw new TraceException("TdhEnumerateProviders failed.", status);
            }

            var buffer = new byte[size];

            fixed (byte* p = buffer)
            {
                status = NativeMethods.TdhEnumerateProviders(p, &size);

                if (status != NativeConstants.ERROR_SUCCESS)
                {
                    throw new TraceException("TdhEnumerateProviders failed.", status);
                }

                var header = (PROVIDER_ENUMERATION_INFO*)p;
                var entries = (TRACE_PROVIDER_INFO*)(p + sizeof(PROVIDER_ENUMERATION_INFO));

                for (uint i = 0; i < header->NumberOfProviders; i++)
                {
                    var candidate = (char*)(p + entries[i].ProviderNameOffset);

                    int j = 0;
                    while (j < name.Length && candidate[j] != '\0' && candidate[j] == name[j])
                    {
                        j++;
                    }

                    if (j == name.Length && candidate[j] == '\0')
                    {
                        return entries[i].ProviderGuid;
                    }
                }
            }

            throw new ArgumentException("Provider name does not exist. (" + name + ")", nameof(name));
        }

        public void Dispose()
        {
        }
    }

    internal static class ErrorMessages
    {
        /// <summary>
        /// Mirrors krabs::get_status_and_record_context so error text is comparable between
        /// the two implementations.
        /// </summary>
        public static string StatusAndRecordContext(int status, Guid providerId, ushort eventId)
        {
            return "status_code=" + ((uint)status).ToString()
                + " provider_id=" + providerId.ToString("D")
                + " event_id=" + eventId.ToString();
        }
    }
}
