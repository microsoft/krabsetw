using System;
using System.Runtime.CompilerServices;
using Microsoft.O365.Security.ETW.Interop;
using Microsoft.O365.Security.ETW.Schema;

namespace Microsoft.O365.Security.ETW
{
    /// <summary>
    /// A zero-copy view over a single ETW event.
    /// </summary>
    /// <remarks>
    /// This is a view, never a container. It holds pointers into the buffer ETW owns, so it
    /// is only valid for the duration of the callback that produced it. Being a ref struct is
    /// what makes that safe: the compiler prevents it from being stored in a field, captured
    /// by a lambda, boxed, or used across an await, so a stale view cannot be constructed.
    ///
    /// Property accessors return spans that point directly into the event payload. Nothing is
    /// copied and nothing is allocated unless the caller explicitly asks for a string.
    /// </remarks>
    public readonly unsafe ref partial struct EventRecordRef
    {
        private readonly EVENT_RECORD* _record;
        private readonly EventScratch _scratch;

        internal EventRecordRef(EVENT_RECORD* record, EventScratch scratch)
        {
            _record = record;
            _scratch = scratch;
        }

        internal EVENT_RECORD* Record
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            get { return _record; }
        }

        /// <summary>
        /// Fetches the schema if it has not been fetched already. Every payload accessor goes
        /// through here, so events rejected on header fields alone never pay for it.
        /// </summary>
        private SchemaEntry Schema
        {
            get { return _scratch.Schema; }
        }

        private OffsetResolver Offsets
        {
            get { return _scratch.Offsets; }
        }

        internal bool HasSchema
        {
            get
            {
                var schema = Schema;
                return schema != null && schema.Table != null;
            }
        }

        /// <summary>TDH status from the schema lookup. Zero means a schema was obtained.</summary>
        internal int SchemaStatus
        {
            get { return Schema.Status; }
        }

        /// <summary>Resolves and returns the schema entry, including a cached failure.</summary>
        internal SchemaEntry SchemaEntry
        {
            get { return Schema; }
        }

        #region Header

        public ushort Id
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            get { return _record->EventHeader.EventDescriptor.Id; }
        }

        public byte Opcode
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            get { return _record->EventHeader.EventDescriptor.Opcode; }
        }

        public byte Version
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            get { return _record->EventHeader.EventDescriptor.Version; }
        }

        public byte Level
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            get { return _record->EventHeader.EventDescriptor.Level; }
        }

        public ulong Keyword
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            get { return _record->EventHeader.EventDescriptor.Keyword; }
        }

        public ushort Flags
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            get { return _record->EventHeader.Flags; }
        }

        public ushort EventProperty
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            get { return _record->EventHeader.EventProperty; }
        }

        public uint ProcessId
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            get { return _record->EventHeader.ProcessId; }
        }

        public uint ThreadId
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            get { return _record->EventHeader.ThreadId; }
        }

        public Guid ProviderId
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            get { return _record->EventHeader.ProviderId; }
        }

        public Guid ActivityId
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            get { return _record->EventHeader.ActivityId; }
        }

        /// <summary>Raw QPC/FILETIME stamp as delivered by ETW.</summary>
        public long RawTimestamp
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            get { return _record->EventHeader.TimeStamp; }
        }

        public DateTime Timestamp
        {
            get { return DateTime.FromFileTimeUtc(_record->EventHeader.TimeStamp); }
        }

        public ushort UserDataLength
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            get { return _record->UserDataLength; }
        }

        public IntPtr UserData
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            get { return _record->UserData; }
        }

        /// <summary>The raw event payload. No copy is made.</summary>
        public ReadOnlySpan<byte> UserDataSpan
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            get { return new ReadOnlySpan<byte>((void*)_record->UserData, _record->UserDataLength); }
        }

        public DecodingSource DecodingSource
        {
            get
            {
                var schema = Schema;
                return schema != null && schema.Table != null
                    ? (DecodingSource)schema.Info->DecodingSource
                    : DecodingSource.Max;
            }
        }

        /// <summary>
        /// Classifies the event from its header alone, without consulting TDH.
        /// </summary>
        /// <remarks>
        /// Port of krabs::get_event_type, whose logic is reverse engineered from
        /// tdh!TdhGetEventInformation. Unlike <see cref="DecodingSource"/> this costs nothing
        /// and works for events that have no schema at all, which is what makes it usable for
        /// routing MOF and WPP events to the right provider.
        /// </remarks>
        public DecodingSource GetEventType()
        {
            return GetEventType(_record);
        }

        internal static DecodingSource GetEventType(EVENT_RECORD* record)
        {
            ushort flags = record->EventHeader.Flags;

            if ((flags & NativeConstants.EVENT_HEADER_FLAG_TRACE_MESSAGE) != 0)
            {
                return DecodingSource.WPP;
            }

            if (record->EventHeader.EventDescriptor.Channel == 11 || HasTraceLoggingSchema(record))
            {
                return DecodingSource.Tlg;
            }

            if ((flags & NativeConstants.EVENT_HEADER_FLAG_CLASSIC_HEADER) != 0)
            {
                return DecodingSource.Wbem;
            }

            return DecodingSource.XMLFile;
        }

        private static bool HasTraceLoggingSchema(EVENT_RECORD* record)
        {
            if (record->ExtendedDataCount == 0 || record->ExtendedData == IntPtr.Zero)
            {
                return false;
            }

            var items = (EVENT_HEADER_EXTENDED_DATA_ITEM*)record->ExtendedData;

            for (int i = 0; i < record->ExtendedDataCount; i++)
            {
                if (items[i].ExtType == NativeConstants.EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL)
                {
                    return true;
                }
            }

            return false;
        }

        #endregion

        #region Schema strings

        /// <summary>Event name, as a view into the cached schema. Does not allocate.</summary>
        public ReadOnlySpan<char> Name
        {
            get
            {
                var schema = Schema;
                return schema == null || schema.Table == null
                    ? default
                    : SchemaString(schema, schema.Info->EventNameOffset);
            }
        }

        public ReadOnlySpan<char> ProviderName
        {
            get
            {
                var schema = Schema;
                return schema == null || schema.Table == null
                    ? default
                    : SchemaString(schema, schema.Info->ProviderNameOffset);
            }
        }

        public ReadOnlySpan<char> TaskName
        {
            get
            {
                var schema = Schema;
                return schema == null || schema.Table == null
                    ? default
                    : SchemaString(schema, schema.Info->TaskNameOffset);
            }
        }

        public ReadOnlySpan<char> OpcodeName
        {
            get
            {
                var schema = Schema;
                return schema == null || schema.Table == null
                    ? default
                    : SchemaString(schema, schema.Info->OpcodeNameOffset);
            }
        }

        private static ReadOnlySpan<char> SchemaString(SchemaEntry schema, uint offset)
        {
            if (offset == 0)
            {
                return default;
            }

            var start = (char*)((byte*)schema.Blob + offset);
            int length = 0;
            while (start[length] != '\0')
            {
                length++;
            }

            return new ReadOnlySpan<char>(start, length);
        }

        #endregion

        #region Property access

        /// <summary>Number of properties described by this event's schema.</summary>
        public int PropertyCount
        {
            get
            {
                var schema = Schema;
                return schema?.Table?.Count ?? 0;
            }
        }

        /// <summary>Resolves a property name to its index, or -1. Does not allocate.</summary>
        public int IndexOf(ReadOnlySpan<char> name)
        {
            var schema = Schema;
            if (schema == null || schema.Table == null)
            {
                return -1;
            }

            return schema.Table.IndexOf(name, (byte*)schema.Blob);
        }

        /// <summary>
        /// Returns the raw bytes of a property, pointing directly into the event payload.
        /// </summary>
        public bool TryGetRaw(int index, out ReadOnlySpan<byte> value)
        {
            value = default;

            var schema = Schema;
            if (schema == null || schema.Table == null)
            {
                return false;
            }

            var offsets = Offsets;

            int offset = offsets.GetOffset(index);
            if (offset < 0)
            {
                return false;
            }

            int size = offsets.SizeOf(index, offset);
            if (size < 0 || offset + size > _record->UserDataLength)
            {
                return false;
            }

            value = new ReadOnlySpan<byte>((byte*)_record->UserData + offset, size);
            return true;
        }

        public bool TryGetRaw(ReadOnlySpan<char> name, out ReadOnlySpan<byte> value)
        {
            int index = IndexOf(name);
            if (index < 0)
            {
                value = default;
                return false;
            }

            return TryGetRaw(index, out value);
        }

        internal ushort InTypeAt(int index)
        {
            var schema = Schema;
            return schema?.Table == null ? (ushort)0 : schema.Table.Properties[index].InType;
        }

        internal ushort OutTypeAt(int index)
        {
            var schema = Schema;
            return schema?.Table == null ? (ushort)0 : schema.Table.Properties[index].OutType;
        }

        internal ReadOnlySpan<char> PropertyNameAt(int index)
        {
            var schema = Schema;
            if (schema?.Table == null)
            {
                return default;
            }

            var table = schema.Table;
            return new ReadOnlySpan<char>((byte*)schema.Blob + table.Properties[index].NameOffset, table.Properties[index].NameLength);
        }

        #endregion
    }

    /// <summary>
    /// From TRACE_EVENT_INFO.DecodingSource.
    /// </summary>
    public enum DecodingSource
    {
        XMLFile,
        Wbem,
        WPP,
        Tlg,
        Max
    }
}
