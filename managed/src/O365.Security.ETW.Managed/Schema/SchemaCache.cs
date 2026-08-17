using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading;
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

        /// <summary>
        /// The event's TraceLogging metadata block, used to disambiguate keys that collide on
        /// hash. Null for events that did not come from the TraceLogging API.
        /// </summary>
        private readonly byte[]? _traceLoggingMetadata;

        /// <summary>
        /// The next entry sharing this entry's key, or null -- which is every entry in a trace
        /// whose schemas do not collide, meaning almost all of them.
        /// </summary>
        /// <remarks>
        /// Two TraceLogging events with the same descriptor whose metadata blocks collide on a
        /// 64-bit FNV hash land on one key. Neither can be misdecoded -- <see cref="MetadataMatches"/>
        /// compares the whole block before any entry is returned -- but replacing one with the
        /// other would make the pair thrash: a TDH lookup per event, and a schema blob added to
        /// the cache's allocation list per event, for the life of the trace. Keeping both costs
        /// a reference nobody follows unless the exact comparison has already failed, which is
        /// the miss path either way.
        /// </remarks>
        public SchemaEntry? Next;

        public SchemaEntry(IntPtr blob, int blobSize, PropertyTable table, byte[]? traceLoggingMetadata)
        {
            Blob = blob;
            BlobSize = blobSize;
            Table = table;
            Status = NativeConstants.ERROR_SUCCESS;
            _traceLoggingMetadata = traceLoggingMetadata;
        }

        public SchemaEntry(int status, byte[]? traceLoggingMetadata)
        {
            Blob = IntPtr.Zero;
            BlobSize = 0;
            Table = null;
            Status = status;
            _traceLoggingMetadata = traceLoggingMetadata;
        }

        public TRACE_EVENT_INFO* Info
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            get { return (TRACE_EVENT_INFO*)Blob; }
        }

        /// <summary>
        /// Whether this entry describes an event carrying the given metadata block.
        /// </summary>
        /// <remarks>
        /// Comparing the whole block, not just the name, is what keeps two same-named
        /// TraceLogging events with different field layouts -- including two versions of one
        /// event during a rolling upgrade -- from sharing an entry and decoding as each other.
        /// </remarks>
        public bool MetadataMatches(ReadOnlySpan<byte> metadata)
        {
            if (_traceLoggingMetadata == null)
            {
                return metadata.Length == 0;
            }

            return ShortSpan.Equal(metadata, _traceLoggingMetadata);
        }
    }

    /// <summary>
    /// Identity of an event schema. Mirrors krabs::schema_key, with the TraceLogging event
    /// name reduced to a hash so lookups never allocate; collisions are resolved by comparing
    /// the stored name.
    /// </summary>
    /// <remarks>
    /// Carries the emitting process's pointer width, which krabs::schema_key does not.
    /// krabs sizes every property afresh for each event, so one cached blob serves both
    /// widths; this cache precomputes the fixed property offsets once per entry, and a
    /// POINTER shifts everything after it, so the two widths need separate entries.
    /// </remarks>
    internal readonly struct SchemaKey : IEquatable<SchemaKey>
    {
        public readonly GuidKey Provider;
        public readonly ulong Keyword;
        public readonly ulong MetadataHash;
        public readonly ushort Id;
        public readonly byte Version;
        public readonly byte Opcode;
        public readonly byte Level;
        public readonly byte PointerSize;

        public SchemaKey(GuidKey provider, ulong keyword, ulong metadataHash, ushort id, byte version, byte opcode, byte level, int pointerSize)
        {
            Provider = provider;
            Keyword = keyword;
            MetadataHash = metadataHash;
            Id = id;
            Version = version;
            Opcode = opcode;
            Level = level;
            PointerSize = (byte)pointerSize;
        }

        /// <summary>
        /// Compares everything except the name hash, which exists only to spread dictionary
        /// buckets. Callers that already hold the name confirm it separately.
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public bool MatchesEvent(GuidKey provider, ulong keyword, ushort id, byte version, byte opcode, byte level, int pointerSize)
        {
            return Id == id
                && Version == version
                && Opcode == opcode
                && Level == level
                && PointerSize == pointerSize
                && Keyword == keyword
                && Provider.Equals(provider);
        }

        public bool Equals(SchemaKey other)
        {
            return Id == other.Id
                && Version == other.Version
                && Opcode == other.Opcode
                && Level == other.Level
                && PointerSize == other.PointerSize
                && Keyword == other.Keyword
                && MetadataHash == other.MetadataHash
                && Provider.Equals(other.Provider);
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
                h = (h * 397) ^ (int)(MetadataHash ^ (MetadataHash >> 32));
                h = (h * 397) ^ Id;
                h = (h * 397) ^ (Version | (Opcode << 8) | (Level << 16) | (PointerSize << 24));
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
        private readonly List<SafeHGlobalHandle> _blobs = new List<SafeHGlobalHandle>();
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
            // The whole metadata block, not just the event name: for a self-describing event
            // the block is the schema, so two events that share a name but not a field layout
            // must not share a cache entry.
            ReadOnlySpan<byte> tlMetadata = TraceLoggingMetadata.GetMetadata(record);

            ref EVENT_DESCRIPTOR descriptor = ref record->EventHeader.EventDescriptor;
            int pointerSize = PointerSizeFor(record);

            // Split once, out of the header. Every comparison below then works on two ulongs
            // rather than copying sixteen bytes into and out of a Guid at each hand-off.
            GuidKey provider = GuidKey.Read(&record->EventHeader.ProviderId);

            // Events arrive in bursts from the same provider, so the previous event's schema
            // is overwhelmingly the right answer. Confirming it structurally is cheaper than
            // hashing the metadata and probing the dictionary.
            if (_lastEntry != null
                && _lastKey.MatchesEvent(
                    provider,
                    descriptor.Keyword,
                    descriptor.Id,
                    descriptor.Version,
                    descriptor.Opcode,
                    descriptor.Level,
                    pointerSize)
                && _lastEntry.MetadataMatches(tlMetadata))
            {
                return _lastEntry;
            }

            ulong metadataHash = tlMetadata.Length == 0 ? 0UL : Fnv1A(tlMetadata);

            var key = new SchemaKey(
                provider,
                descriptor.Keyword,
                metadataHash,
                descriptor.Id,
                descriptor.Version,
                descriptor.Opcode,
                descriptor.Level,
                pointerSize);

            if (_cache.TryGetValue(key, out SchemaEntry? head))
            {
                if (head.MetadataMatches(tlMetadata))
                {
                    _lastKey = key;
                    _lastEntry = head;
                    return head;
                }

                // Only reachable when two distinct metadata blocks hash to the same key, so
                // the walk is off the path every well-behaved trace takes.
                for (SchemaEntry? candidate = head.Next; candidate != null; candidate = candidate.Next)
                {
                    if (candidate.MetadataMatches(tlMetadata))
                    {
                        _lastKey = key;
                        _lastEntry = candidate;
                        return candidate;
                    }
                }

                SchemaEntry collided = Load(record, tlMetadata);
                Misses++;

                // Prepend: the entry just resolved is the one the next event is likeliest to
                // want, and the chain is only ever walked after an exact comparison failed.
                collided.Next = head;
                _cache[key] = collided;
                _lastKey = key;
                _lastEntry = collided;
                return collided;
            }

            SchemaEntry entry = Load(record, tlMetadata);
            Misses++;
            _cache[key] = entry;
            _lastKey = key;
            _lastEntry = entry;
            return entry;
        }

        private SchemaEntry Load(EVENT_RECORD* record, ReadOnlySpan<byte> tlMetadata)
        {
            byte[]? metadataCopy = tlMetadata.Length == 0 ? null : tlMetadata.ToArray();

            if (Testing.DeclaredSchemas.Any)
            {
                SchemaEntry? declared = LoadDeclared(record, metadataCopy);

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
                    : status, metadataCopy);
            }

            var allocation = new SafeHGlobalHandle((int)size);
            IntPtr blob = allocation.Pointer;
            status = NativeMethods.TdhGetEventInformation(record, 0, IntPtr.Zero, (TRACE_EVENT_INFO*)blob, &size);

            if (status != NativeConstants.ERROR_SUCCESS)
            {
                allocation.Dispose();
                return new SchemaEntry(status, metadataCopy);
            }

            // The list owns the allocation for the life of the cache; the entry keeps the raw
            // pointer so reads stay a plain dereference.
            _blobs.Add(allocation);

            int pointerSize = PointerSizeFor(record);
            var table = new PropertyTable((TRACE_EVENT_INFO*)blob, pointerSize);

            return new SchemaEntry(blob, (int)size, table, metadataCopy);
        }

        /// <summary>
        /// Renders a schema declared by a test into the same unmanaged form TDH returns, so
        /// nothing downstream can tell the difference. Returns null when no declaration
        /// covers the event, leaving TDH to answer.
        /// </summary>
        private SchemaEntry? LoadDeclared(EVENT_RECORD* record, byte[]? metadataCopy)
        {
            ref EVENT_DESCRIPTOR descriptor = ref record->EventHeader.EventDescriptor;

            Testing.EventSchema? declaration = Testing.DeclaredSchemas.Find(
                record->EventHeader.ProviderId, descriptor.Id, descriptor.Version);

            if (declaration == null)
            {
                return null;
            }

            byte[] source = declaration.Blob();
            var allocation = new SafeHGlobalHandle(source.Length);
            IntPtr blob = allocation.Pointer;
            Marshal.Copy(source, 0, blob, source.Length);
            _blobs.Add(allocation);

            var table = new PropertyTable((TRACE_EVENT_INFO*)blob, PointerSizeFor(record));

            return new SchemaEntry(blob, source.Length, table, metadataCopy);
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

        /// <summary>
        /// Releases the cached schema blobs.
        /// </summary>
        /// <remarks>
        /// No finalizer: each blob is a <see cref="SafeHGlobalHandle"/> and releases itself
        /// through its own critical finalizer if the cache is abandoned. Disposing here just
        /// makes it deterministic.
        /// </remarks>
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
                _blobs[i].Dispose();
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
        /// The event's TraceLogging metadata block, or empty when the event did not come from
        /// the TraceLogging API.
        /// </summary>
        /// <remarks>
        /// This block *is* the schema for a self-describing event: it carries the name and
        /// every field descriptor. Two events sharing a name but not a field layout have
        /// different blocks, which is why the cache keys on the whole thing rather than the
        /// name alone.
        ///
        /// The block is a packed pseudo-struct:
        ///   UINT16 Size;
        ///   UINT8  Extension[];  // read until a byte has its high bit clear
        ///   char   Name[];       // UTF-8, NUL terminated
        ///   ...    field descriptors follow
        /// </remarks>
        public static ReadOnlySpan<byte> GetMetadata(EVENT_RECORD* record)
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

            return new ReadOnlySpan<byte>(metadata, structSize);
        }

        /// <summary>
        /// Returns the TraceLogging event name as UTF-8, or an empty span when the event was
        /// not produced by the TraceLogging API.
        /// </summary>
        /// <remarks>
        /// Reimplements part of what TDH would otherwise do, so a schema key can be built
        /// without calling TDH. Mirrors krabs::get_trace_logger_event_name.
        ///
        /// Sliced from the block rather than walked with a pointer: taking a pointer with
        /// `fixed` and returning a span built from it would be correct only for as long as
        /// the block happens to be unmanaged memory, and would silently become a
        /// use-after-unpin the day it was not.
        /// </remarks>
        public static ReadOnlySpan<byte> GetEventName(EVENT_RECORD* record)
        {
            ReadOnlySpan<byte> block = GetMetadata(record);

            if (block.Length == 0)
            {
                return default;
            }

            int nameOffset = sizeof(ushort);
            while (nameOffset < block.Length)
            {
                byte b = block[nameOffset];
                nameOffset++;

                if ((b & 0x80) != 0x80)
                {
                    break;
                }
            }

            if (nameOffset >= block.Length)
            {
                return default;
            }

            ReadOnlySpan<byte> rest = block.Slice(nameOffset);
            int terminator = rest.IndexOf((byte)0);

            return terminator < 0 ? rest : rest.Slice(0, terminator);
        }
    }
}
