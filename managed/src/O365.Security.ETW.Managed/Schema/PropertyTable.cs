using System;
using System.Runtime.CompilerServices;
using Microsoft.O365.Security.ETW.Interop;

namespace Microsoft.O365.Security.ETW.Schema
{
    /// <summary>
    /// Precomputed, per-schema description of an event's properties.
    /// </summary>
    /// <remarks>
    /// Native krabs performs a hinted linear scan over property names on every lookup.
    /// We pay the name-walk once, when the schema is first seen, and index thereafter.
    /// Parallel arrays are used deliberately: the hot path only touches <see cref="NameSignatures"/>
    /// until a candidate matches, which keeps the scan inside one or two cache lines.
    /// </remarks>
    internal sealed unsafe class PropertyTable
    {
        public readonly int Count;

        /// <summary>Hash of each property name, scanned linearly on lookup.</summary>
        public readonly ulong[] NameSignatures;

        /// <summary>Byte offset of each property name (UTF-16, NUL terminated) within the schema blob.</summary>
        public readonly int[] NameOffsets;

        /// <summary>Length in characters of each property name, excluding the terminator.</summary>
        public readonly int[] NameLengths;

        public readonly ushort[] InTypes;
        public readonly ushort[] OutTypes;
        public readonly uint[] Flags;

        /// <summary>Static length from the schema, or the index of the length property when PropertyParamLength is set.</summary>
        public readonly ushort[] Lengths;

        /// <summary>Static count from the schema, or the index of the count property when PropertyParamCount is set.</summary>
        public readonly ushort[] Counts;

        /// <summary>
        /// Byte offset of each property from the start of UserData when every preceding property
        /// has a schema-known fixed size, otherwise -1 (offset must be resolved by walking).
        /// </summary>
        public readonly int[] FixedOffsets;

        /// <summary>Index of the first property whose offset cannot be precomputed, or Count if all are fixed.</summary>
        public readonly int FirstDynamicIndex;

        /// <summary>
        /// Index at which the next name scan starts. Callers read properties in event order,
        /// so resuming after the last hit usually turns the scan into a single comparison.
        /// </summary>
        private int _hint;

        public PropertyTable(TRACE_EVENT_INFO* schema, int pointerSize)
        {
            Count = (int)schema->PropertyCount;
            NameSignatures = new ulong[Count];
            NameOffsets = new int[Count];
            NameLengths = new int[Count];
            InTypes = new ushort[Count];
            OutTypes = new ushort[Count];
            Flags = new uint[Count];
            Lengths = new ushort[Count];
            Counts = new ushort[Count];
            FixedOffsets = new int[Count];

            var props = (EVENT_PROPERTY_INFO*)((byte*)schema + TraceEventInfoLayout.PropertyArrayOffset);
            var blob = (byte*)schema;

            int runningOffset = 0;
            bool stillFixed = true;
            int firstDynamic = Count;

            for (int i = 0; i < Count; i++)
            {
                ref EVENT_PROPERTY_INFO p = ref props[i];

                Flags[i] = p.Flags;
                InTypes[i] = p.InTypeOrStructStartIndex;
                OutTypes[i] = p.OutTypeOrNumOfStructMembers;
                Lengths[i] = p.LengthOrLengthPropertyIndex;
                Counts[i] = p.CountOrCountPropertyIndex;

                int nameOffset = (int)p.NameOffset;
                NameOffsets[i] = nameOffset;

                int nameLength = 0;
                if (nameOffset > 0)
                {
                    var name = (char*)(blob + nameOffset);
                    while (name[nameLength] != '\0')
                    {
                        nameLength++;
                    }
                }

                NameLengths[i] = nameLength;
                NameSignatures[i] = nameOffset > 0
                    ? NameSignature.Compute(new ReadOnlySpan<char>(blob + nameOffset, nameLength))
                    : 0UL;
                if (stillFixed)
                {
                    FixedOffsets[i] = runningOffset;

                    int size = PropertySizer.TryGetFixedSize(
                        p.Flags,
                        p.InTypeOrStructStartIndex,
                        p.OutTypeOrNumOfStructMembers,
                        p.LengthOrLengthPropertyIndex,
                        p.CountOrCountPropertyIndex,
                        pointerSize);

                    if (size < 0)
                    {
                        // This property's size depends on the payload, so every subsequent
                        // offset must be resolved by walking the event at runtime.
                        stillFixed = false;
                        firstDynamic = i + 1;
                    }
                    else
                    {
                        runningOffset += size;
                    }
                }
                else
                {
                    FixedOffsets[i] = -1;
                }
            }

            FirstDynamicIndex = stillFixed ? Count : firstDynamic;
        }

        /// <summary>
        /// Finds a property index by name without allocating.
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public int IndexOf(ReadOnlySpan<char> name, byte* blob)
        {
            ulong signature = NameSignature.Compute(name);
            var signatures = NameSignatures;
            int count = signatures.Length;
            int start = _hint;

            for (int n = 0; n < count; n++)
            {
                int i = start + n;
                if (i >= count)
                {
                    i -= count;
                }

                if (signatures[i] != signature)
                {
                    continue;
                }

                // The signature already agrees on length; confirm the rest to rule out collisions.
                if (ShortSpan.Equal((char*)(blob + NameOffsets[i]), name))
                {
                    int next = i + 1;
                    _hint = next == count ? 0 : next;
                    return i;
                }
            }

            return -1;
        }
    }

    internal static class TraceEventInfoLayout
    {
        /// <summary>
        /// Offset of TRACE_EVENT_INFO.EventPropertyInfoArray, verified against the Windows
        /// headers by managed/tools/layoutprobe.
        /// </summary>
        public const int PropertyArrayOffset = 112;
    }

    /// <summary>
    /// A cheap fixed-cost signature of a property name, used to reject non-matching entries
    /// during the linear scan. Only used for in-memory lookup, never persisted.
    /// </summary>
    /// <remarks>
    /// A real hash (this was FNV-1a) walks every character through a serially dependent
    /// multiply chain, which measured as the dominant cost of a property lookup - more than
    /// the scan it was meant to accelerate. Property names are short and share few
    /// length/first/middle/last combinations, so this rejects just as effectively at a
    /// constant handful of instructions. Survivors are confirmed by comparing the real name,
    /// so collisions cost time but never correctness.
    /// </remarks>
    internal static class NameSignature
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static ulong Compute(ReadOnlySpan<char> value)
        {
            int length = value.Length;

            if (length == 0)
            {
                // Distinct from the zero stored for properties that carry no name at all.
                return 1UL;
            }

            return (uint)length
                | ((ulong)value[0] << 16)
                | ((ulong)value[length - 1] << 32)
                | ((ulong)value[length >> 1] << 48);
        }
    }
}
