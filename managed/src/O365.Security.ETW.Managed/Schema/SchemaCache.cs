using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Microsoft.O365.Security.ETW.Interop;

namespace Microsoft.O365.Security.ETW.Schema
{
    /// <summary>
    /// A cached schema, or a cached failure to obtain one.
    /// </summary>
    internal sealed unsafe class SchemaEntry
    {
        /// <summary>Unmanaged TRACE_EVENT_INFO blob. Off the GC heap so it never moves and needs no pinning.</summary>
        public readonly IntPtr Blob;

        public readonly int BlobSize;

        /// <summary>TDH status. ERROR_SUCCESS means <see cref="Blob"/> and <see cref="Table"/> are valid.</summary>
        public readonly int Status;

        public readonly PropertyTable? Table;

        /// <summary>TraceLogging event name, used to disambiguate keys that collide on hash.</summary>
        private readonly byte[]? _traceLoggingName;

        public SchemaEntry(IntPtr blob, int blobSize, PropertyTable table, byte[]? traceLoggingName)
        {
            Blob = blob;
            BlobSize = blobSize;
            Table = table;
            Status = NativeConstants.ERROR_SUCCESS;
            _traceLoggingName = traceLoggingName;
        }

        public SchemaEntry(int status, byte[]? traceLoggingName)
        {
            Blob = IntPtr.Zero;
            BlobSize = 0;
            Table = null;
            Status = status;
            _traceLoggingName = traceLoggingName;
        }

        public TRACE_EVENT_INFO* Info
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            get { return (TRACE_EVENT_INFO*)Blob; }
        }

        public bool NameMatches(ReadOnlySpan<byte> name)
        {
            if (_traceLoggingName == null)
            {
                return name.Length == 0;
            }

            return ShortSpan.Equal(name, _traceLoggingName);
        }
    }

    /// <summary>
    /// Identity of an event schema. Mirrors krabs::schema_key, with the TraceLogging event
    /// name reduced to a hash so lookups never allocate; collisions are resolved by comparing
    /// the stored name.
    /// </summary>
    internal readonly struct SchemaKey : IEquatable<SchemaKey>
    {
        public readonly Guid Provider;
        public readonly ulong Keyword;
        public readonly ulong NameHash;
        public readonly ushort Id;
        public readonly byte Version;
        public readonly byte Opcode;
        public readonly byte Level;

        public SchemaKey(Guid provider, ulong keyword, ulong nameHash, ushort id, byte version, byte opcode, byte level)
        {
            Provider = provider;
            Keyword = keyword;
            NameHash = nameHash;
            Id = id;
            Version = version;
            Opcode = opcode;
            Level = level;
        }

        /// <summary>
        /// Compares everything except the name hash, which exists only to spread dictionary
        /// buckets. Callers that already hold the name confirm it separately.
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public bool MatchesEvent(Guid provider, ulong keyword, ushort id, byte version, byte opcode, byte level)
        {
            return Id == id
                && Version == version
                && Opcode == opcode
                && Level == level
                && Keyword == keyword
                && Provider == provider;
        }

        public bool Equals(SchemaKey other)
        {
            return Id == other.Id
                && Version == other.Version
                && Opcode == other.Opcode
                && Level == other.Level
                && Keyword == other.Keyword
                && NameHash == other.NameHash
                && Provider == other.Provider;
        }

        public override bool Equals(object? obj)
        {
            return obj is SchemaKey other && Equals(other);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                int h = Provider.GetHashCode();
                h = (h * 397) ^ (int)(Keyword ^ (Keyword >> 32));
                h = (h * 397) ^ (int)(NameHash ^ (NameHash >> 32));
                h = (h * 397) ^ Id;
                h = (h * 397) ^ (Version | (Opcode << 8) | (Level << 16));
                return h;
            }
        }
    }

    /// <summary>
    /// Fetches and caches event schemas from TDH. Port of krabs::schema_locator.
    /// </summary>
    /// <remarks>
    /// Not thread safe by design: ProcessTrace delivers events for a trace on a single
    /// thread, and each trace owns its own cache.
    /// </remarks>
    internal sealed unsafe class SchemaCache : IDisposable
    {
        private readonly Dictionary<SchemaKey, SchemaEntry> _cache = new Dictionary<SchemaKey, SchemaEntry>();
        private readonly List<IntPtr> _blobs = new List<IntPtr>();
        private SchemaKey _lastKey;
        private SchemaEntry? _lastEntry;
        private bool _disposed;

        /// <summary>Number of TDH lookups performed. A well-behaved trace resolves each distinct schema once.</summary>
        internal int Misses { get; private set; }

        /// <summary>
        /// Returns the cached schema for an event, consulting TDH on a miss. Failures are
        /// cached too, so an event without a schema is only looked up once.
        /// </summary>
        public SchemaEntry Get(EVENT_RECORD* record)
        {
            ReadOnlySpan<byte> tlName = TraceLoggingMetadata.GetEventName(record);

            ref EVENT_DESCRIPTOR descriptor = ref record->EventHeader.EventDescriptor;

            // Events arrive in bursts from the same provider, so the previous event's schema
            // is overwhelmingly the right answer. Confirming it structurally is cheaper than
            // hashing the name and probing the dictionary.
            if (_lastEntry != null
                && _lastKey.MatchesEvent(
                    record->EventHeader.ProviderId,
                    descriptor.Keyword,
                    descriptor.Id,
                    descriptor.Version,
                    descriptor.Opcode,
                    descriptor.Level)
                && _lastEntry.NameMatches(tlName))
            {
                return _lastEntry;
            }

            ulong nameHash = tlName.Length == 0 ? 0UL : Fnv1A(tlName);

            var key = new SchemaKey(
                record->EventHeader.ProviderId,
                descriptor.Keyword,
                nameHash,
                descriptor.Id,
                descriptor.Version,
                descriptor.Opcode,
                descriptor.Level);

            if (_cache.TryGetValue(key, out SchemaEntry? entry) && entry.NameMatches(tlName))
            {
                _lastKey = key;
                _lastEntry = entry;
                return entry;
            }

            entry = Load(record, tlName);
            Misses++;
            _cache[key] = entry;
            _lastKey = key;
            _lastEntry = entry;
            return entry;
        }

        private SchemaEntry Load(EVENT_RECORD* record, ReadOnlySpan<byte> tlName)
        {
            byte[]? nameCopy = tlName.Length == 0 ? null : tlName.ToArray();

            if (Testing.DeclaredSchemas.Any)
            {
                SchemaEntry? declared = LoadDeclared(record, nameCopy);

                if (declared != null)
                {
                    return declared;
                }
            }

            uint size = 0;
            int status = NativeMethods.TdhGetEventInformation(record, 0, IntPtr.Zero, null, &size);

            if (status != NativeConstants.ERROR_INSUFFICIENT_BUFFER)
            {
                return new SchemaEntry(status == NativeConstants.ERROR_SUCCESS
                    ? NativeConstants.ERROR_NOT_FOUND
                    : status, nameCopy);
            }

            IntPtr blob = Marshal.AllocHGlobal((int)size);
            status = NativeMethods.TdhGetEventInformation(record, 0, IntPtr.Zero, (TRACE_EVENT_INFO*)blob, &size);

            if (status != NativeConstants.ERROR_SUCCESS)
            {
                Marshal.FreeHGlobal(blob);
                return new SchemaEntry(status, nameCopy);
            }

            _blobs.Add(blob);

            int pointerSize = PointerSizeFor(record);
            var table = new PropertyTable((TRACE_EVENT_INFO*)blob, pointerSize);

            return new SchemaEntry(blob, (int)size, table, nameCopy);
        }

        /// <summary>
        /// Renders a schema declared by a test into the same unmanaged form TDH returns, so
        /// nothing downstream can tell the difference. Returns null when no declaration
        /// covers the event, leaving TDH to answer.
        /// </summary>
        private SchemaEntry? LoadDeclared(EVENT_RECORD* record, byte[]? nameCopy)
        {
            ref EVENT_DESCRIPTOR descriptor = ref record->EventHeader.EventDescriptor;

            Testing.EventSchema? declaration = Testing.DeclaredSchemas.Find(
                record->EventHeader.ProviderId, descriptor.Id, descriptor.Version);

            if (declaration == null)
            {
                return null;
            }

            byte[] source = declaration.Blob();
            IntPtr blob = Marshal.AllocHGlobal(source.Length);
            Marshal.Copy(source, 0, blob, source.Length);
            _blobs.Add(blob);

            var table = new PropertyTable((TRACE_EVENT_INFO*)blob, PointerSizeFor(record));

            return new SchemaEntry(blob, source.Length, table, nameCopy);
        }

        /// <summary>
        /// Pointer width of the process that emitted the event, which governs the size of
        /// TDH_INTYPE_POINTER properties.
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static int PointerSizeFor(EVENT_RECORD* record)
        {
            ushort flags = record->EventHeader.Flags;

            if ((flags & NativeConstants.EVENT_HEADER_FLAG_32_BIT_HEADER) != 0)
            {
                return 4;
            }

            if ((flags & NativeConstants.EVENT_HEADER_FLAG_64_BIT_HEADER) != 0)
            {
                return 8;
            }

            return IntPtr.Size;
        }

        /// <summary>Exposed for benchmarks that isolate the stages of a lookup.</summary>
        internal static ulong HashName(ReadOnlySpan<byte> name)
        {
            return name.Length == 0 ? 0UL : Fnv1A(name);
        }

        private static ulong Fnv1A(ReadOnlySpan<byte> value)        {
            const ulong offsetBasis = 14695981039346656037UL;
            const ulong prime = 1099511628211UL;

            ulong hash = offsetBasis;
            for (int i = 0; i < value.Length; i++)
            {
                hash ^= value[i];
                hash *= prime;
            }

            return hash;
        }

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            _lastEntry = null;

            for (int i = 0; i < _blobs.Count; i++)
            {
                Marshal.FreeHGlobal(_blobs[i]);
            }

            _blobs.Clear();
            _cache.Clear();
        }
    }

    /// <summary>
    /// Parses the TraceLogging metadata block carried in an event's extended data.
    /// </summary>
    internal static unsafe class TraceLoggingMetadata
    {
        /// <summary>
        /// Returns the TraceLogging event name as UTF-8, or an empty span when the event was
        /// not produced by the TraceLogging API.
        /// </summary>
        /// <remarks>
        /// Reimplements part of what TDH would otherwise do, so a schema key can be built
        /// without calling TDH. Mirrors krabs::get_trace_logger_event_name.
        ///
        /// The metadata block is a packed pseudo-struct:
        ///   UINT16 Size;
        ///   UINT8  Extension[];  // read until a byte has its high bit clear
        ///   char   Name[];       // UTF-8, NUL terminated
        /// </remarks>
        public static ReadOnlySpan<byte> GetEventName(EVENT_RECORD* record)
        {
            if (record->ExtendedDataCount == 0 || record->ExtendedData == IntPtr.Zero)
            {
                return default;
            }

            var items = (EVENT_HEADER_EXTENDED_DATA_ITEM*)record->ExtendedData;

            byte* metadata = null;
            ushort metadataSize = 0;

            for (int i = 0; i < record->ExtendedDataCount; i++)
            {
                if (items[i].ExtType == NativeConstants.EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL)
                {
                    metadataSize = items[i].DataSize;
                    metadata = (byte*)items[i].DataPtr;
                    break;
                }
            }

            if (metadata == null || metadataSize < sizeof(ushort))
            {
                return default;
            }

            // Guard against reading past the block.
            ushort structSize = (ushort)(metadata[0] | (metadata[1] << 8));
            if (structSize != metadataSize)
            {
                return default;
            }

            int nameOffset = sizeof(ushort);
            while (nameOffset < structSize)
            {
                byte b = metadata[nameOffset];
                nameOffset++;

                if ((b & 0x80) != 0x80)
                {
                    break;
                }
            }

            if (nameOffset >= structSize)
            {
                return default;
            }

            int available = structSize - nameOffset;
            int terminator = ShortSpan.IndexOfZero(metadata + nameOffset, available);

            return new ReadOnlySpan<byte>(metadata + nameOffset, terminator < 0 ? available : terminator);        }
    }
}
