using System;
using System.Runtime.CompilerServices;
using O365.Security.ETW.Interop;

namespace O365.Security.ETW.Schema
{
    /// <summary>
    /// Resolves the byte offset of each property within an event's UserData.
    /// </summary>
    /// <remarks>
    /// Offsets before the first payload-dependent property come straight from the schema.
    /// Beyond that point the payload must be walked in order, so results are memoised against
    /// a high-water mark: accessing property N walks at most from the last resolved property
    /// to N, once per event, rather than from the start on every access.
    ///
    /// One instance is owned by each trace context and reused for every event, so steady-state
    /// operation performs no allocation.
    /// </remarks>
    internal sealed unsafe class OffsetResolver
    {
        private int[] _offsets = new int[32];
        private PropertyTable _table;
        private EVENT_RECORD* _record;
        private byte* _data;
        private int _dataLength;
        private int _pointerSize;

        /// <summary>Number of properties whose offsets are already known.</summary>
        private int _resolved;

        /// <summary>Set when the payload could not be decoded; all further lookups fail.</summary>
        private bool _broken;

        public void Begin(EVENT_RECORD* record, SchemaEntry schema)
        {
            _record = record;
            _table = schema.Table;
            _data = (byte*)record->UserData;
            _dataLength = record->UserDataLength;
            _pointerSize = SchemaCache.PointerSizeFor(record);
            _broken = false;

            if (_table == null)
            {
                _resolved = 0;
                return;
            }

            if (_offsets.Length < _table.Count)
            {
                _offsets = new int[Math.Max(_table.Count, _offsets.Length * 2)];
            }

            // Offsets up to the first payload-dependent property are schema-known.
            _resolved = _table.FirstDynamicIndex;
            for (int i = 0; i < _resolved; i++)
            {
                _offsets[i] = _table.FixedOffsets[i];
            }
        }

        /// <summary>
        /// Returns the offset of a property within UserData, or -1 when it cannot be resolved.
        /// </summary>
        public int GetOffset(int index)
        {
            if (_broken || _table == null || index < 0 || index >= _table.Count)
            {
                return -1;
            }

            if (index < _resolved)
            {
                return _offsets[index];
            }

            // Walk forward from the last known offset, memoising as we go.
            while (_resolved <= index)
            {
                int previous = _resolved - 1;
                if (previous < 0)
                {
                    _broken = true;
                    return -1;
                }

                int previousOffset = _offsets[previous];
                int size = SizeOf(previous, previousOffset);

                if (size < 0)
                {
                    _broken = true;
                    return -1;
                }

                int next = previousOffset + size;
                if (next > _dataLength)
                {
                    _broken = true;
                    return -1;
                }

                _offsets[_resolved] = next;
                _resolved++;
            }

            return _offsets[index];
        }

        /// <summary>
        /// Returns the size in bytes of a property, resolving payload-derived lengths and counts.
        /// </summary>
        public int SizeOf(int index, int offset)
        {
            uint flags = _table.Flags[index];

            if ((flags & NativeConstants.PropertyStruct) != 0)
            {
                // Nested structs are not decoded in this milestone; treat as undecodable so
                // callers fail loudly instead of reading misaligned data.
                return -1;
            }

            ushort length = _table.Lengths[index];
            if ((flags & NativeConstants.PropertyParamLength) != 0)
            {
                if (!TryReadUnsigned(_table.Lengths[index], out ulong dynamicLength))
                {
                    return -1;
                }

                length = (ushort)dynamicLength;
            }

            int count = _table.Counts[index];
            if ((flags & NativeConstants.PropertyParamCount) != 0)
            {
                if (!TryReadUnsigned(_table.Counts[index], out ulong dynamicCount))
                {
                    return -1;
                }

                count = (int)dynamicCount;
            }

            int remaining = _dataLength - offset;
            if (remaining < 0)
            {
                return -1;
            }

            return PropertySizer.GetRuntimeSize(
                _table.InTypes[index],
                length,
                count,
                _pointerSize,
                _data + offset,
                remaining);
        }

        /// <summary>
        /// Reads an integer property by index. Used for payload-derived lengths and counts,
        /// which always reference an earlier property.
        /// </summary>
        private bool TryReadUnsigned(int index, out ulong value)
        {
            value = 0;

            int offset = GetOffset(index);
            if (offset < 0)
            {
                return false;
            }

            int size = PropertySizer.TryGetFixedElementSize(_table.InTypes[index], _table.Lengths[index], _pointerSize);
            if (size < 0 || offset + size > _dataLength)
            {
                return false;
            }

            byte* p = _data + offset;
            switch (size)
            {
                case 1:
                    value = *p;
                    return true;
                case 2:
                    value = Unsafe.ReadUnaligned<ushort>(p);
                    return true;
                case 4:
                    value = Unsafe.ReadUnaligned<uint>(p);
                    return true;
                case 8:
                    value = Unsafe.ReadUnaligned<ulong>(p);
                    return true;
                default:
                    return false;
            }
        }
    }
}
