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
    /// </remarks>
    /// <summary>
    /// Everything the decoder needs to know about one property, in one place.
    /// </summary>
    /// <remarks>
    /// Deliberately one struct rather than a set of parallel arrays. Two reasons, both
    /// measured. The average event has 3.68 properties and the median has 2, so nine separate
    /// arrays meant nine object headers dwarfing the data: a two-property table allocated
    /// 400 bytes to hold about 64 bytes of it. And the sizing path reads the flags, in-type,
    /// out-type, length and count of the *same* property together, which parallel arrays
    /// spread across five cache lines.
    ///
    /// The fields are ordered widest-first, so the runtime needs no padding to keep every one
    /// naturally aligned and the struct lands on exactly 24 bytes. That is a consequence of
    /// the ordering, not of forced packing -- there is no <c>Pack</c> attribute here, so if a
    /// field were added out of order the runtime would insert padding rather than misalign
    /// it. Verified: all four 32-bit fields sit at offsets 0/4/8/12 and all four 16-bit fields
    /// at 16/18/20/22, and an array strides by 24, which keeps every element 8-aligned.
    /// </remarks>
    internal readonly struct PropertyInfo
    {
        /// <summary>Byte offset of the property name (UTF-16, NUL terminated) within the schema blob.</summary>
        public readonly int NameOffset;

        /// <summary>Length in characters of the property name, excluding the terminator.</summary>
        public readonly int NameLength;

        /// <summary>
        /// Byte offset from the start of UserData when every preceding property has a
        /// schema-known fixed size, otherwise -1.
        /// </summary>
        public readonly int FixedOffset;

        public readonly uint Flags;
        public readonly ushort InType;
        public readonly ushort OutType;

        /// <summary>Static length, or the index of the length property when PropertyParamLength is set.</summary>
        public readonly ushort Length;

        /// <summary>Static count, or the index of the count property when PropertyParamCount is set.</summary>
        public readonly ushort Count;

        public PropertyInfo(int nameOffset, int nameLength, int fixedOffset, uint flags, ushort inType, ushort outType, ushort length, ushort count)
        {
            NameOffset = nameOffset;
            NameLength = nameLength;
            FixedOffset = fixedOffset;
            Flags = flags;
            InType = inType;
            OutType = outType;
            Length = length;
            Count = count;
        }
    }

    internal sealed unsafe class PropertyTable
    {
        public readonly int Count;

        /// <summary>
        /// Hash of each property name, kept apart from <see cref="Properties"/> so a lookup
        /// scans a tight array of them rather than striding over 24-byte records.
        /// </summary>
        public readonly ulong[] NameSignatures;

        /// <summary>Per-property metadata, indexed alike with <see cref="NameSignatures"/>.</summary>
        public readonly PropertyInfo[] Properties;

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
            Properties = new PropertyInfo[Count];

            var props = (EVENT_PROPERTY_INFO*)((byte*)schema + TraceEventInfoLayout.PropertyArrayOffset);
            var blob = (byte*)schema;

            int runningOffset = 0;
            bool stillFixed = true;
            int firstDynamic = Count;

            for (int i = 0; i < Count; i++)
            {
                ref EVENT_PROPERTY_INFO p = ref props[i];

                int nameOffset = (int)p.NameOffset;

                int nameLength = 0;
                if (nameOffset > 0)
                {
                    var name = (char*)(blob + nameOffset);
                    while (name[nameLength] != '\0')
                    {
                        nameLength++;
                    }
                }

                NameSignatures[i] = nameOffset > 0
                    ? NameSignature.Compute(new ReadOnlySpan<char>(blob + nameOffset, nameLength))
                    : 0UL;

                int fixedOffset = -1;

                if (stillFixed)
                {
                    fixedOffset = runningOffset;

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

                Properties[i] = new PropertyInfo(
                    nameOffset,
                    nameLength,
                    fixedOffset,
                    p.Flags,
                    p.InTypeOrStructStartIndex,
                    p.OutTypeOrNumOfStructMembers,
                    p.LengthOrLengthPropertyIndex,
                    p.CountOrCountPropertyIndex);
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

            // The hint is checked on its own so the scan below can be a plain ascending walk
            // bounded by the array's own length, which is the shape RyuJIT needs to drop the
            // bounds check. A rotating start index defeats that: the JIT cannot prove a
            // wrapped `start + n` stays in range.
            int hint = _hint;
            if ((uint)hint < (uint)signatures.Length &&
                signatures[hint] == signature &&
                ShortSpan.Equal((char*)(blob + Properties[hint].NameOffset), name))
            {
                Advance(hint, signatures.Length);
                return hint;
            }

            for (int i = 0; i < signatures.Length; i++)
            {
                if (signatures[i] != signature)
                {
                    continue;
                }

                // The signature already agrees on length; confirm the rest to rule out collisions.
                if (ShortSpan.Equal((char*)(blob + Properties[i].NameOffset), name))
                {
                    Advance(i, signatures.Length);
                    return i;
                }
            }

            return -1;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void Advance(int matched, int count)
        {
            int next = matched + 1;
            _hint = next == count ? 0 : next;
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
