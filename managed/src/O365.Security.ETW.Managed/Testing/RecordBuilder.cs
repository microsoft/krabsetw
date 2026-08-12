using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.O365.Security.ETW.Interop;
using Microsoft.O365.Security.ETW.Schema;

namespace Microsoft.O365.Security.ETW.Testing
{
    /// <summary>
    /// EVENT_HEADER.Flags values.
    /// </summary>
    public enum EventHeaderFlags : ushort
    {
        EXTENDED_INFO = 0x0001,
        PRIVATE_SESSION = 0x0002,
        STRING_ONLY = 0x0004,
        TRACE_MESSAGE = 0x0008,
        NO_CPUTIME = 0x0010,
        HEADER_32_BIT = 0x0020,
        HEADER_64_BIT = 0x0040,
        CLASSIC_HEADER = 0x0100,
        PROCESSOR_INDEX = 0x0200
    }

    /// <summary>
    /// Provides access to the EVENT_HEADER of a record being built.
    /// </summary>
    public sealed class EventHeaderView
    {
        private readonly RecordBuilder _builder;

        internal EventHeaderView(RecordBuilder builder)
        {
            _builder = builder;
        }

        public ushort Flags
        {
            get { return _builder.HeaderFlags; }
            set { _builder.HeaderFlags = value; }
        }
    }

    /// <summary>
    /// Enables creation of synthetic events in order to test client code.
    /// </summary>
    /// <remarks>
    /// Properties are supplied by name and are then packed in the order the machine's schema
    /// for the event declares them. Port of krabs::testing::record_builder, including its
    /// quirks: an unfilled property is padded with the fill width its in-type implies rather
    /// than its real schema width, and a supplied property whose type does not match the
    /// schema is rejected.
    /// </remarks>
    public sealed unsafe class RecordBuilder : IDisposable
    {
        private readonly List<PropertyThunk> _properties = new List<PropertyThunk>();
        private readonly ExtendedDataBuilder _extendedData = new ExtendedDataBuilder();
        private readonly bool _trimStringNullTerminator;

        private EVENT_HEADER _header;

        public RecordBuilder(Guid providerId, int id, int version)
            : this(providerId, id, version, 0, 0, 0, false)
        {
        }

        public RecordBuilder(Guid providerId, int id, int version, int opcode)
            : this(providerId, id, version, opcode, 0, 0, false)
        {
        }

        public RecordBuilder(Guid providerId, int id, int version, int opcode, int level, ulong keyword, bool trimStringNullTerminator)
        {
            _header = default(EVENT_HEADER);
            _header.ProviderId = providerId;
            _header.EventDescriptor.Id = (ushort)id;
            _header.EventDescriptor.Version = (byte)version;
            _header.EventDescriptor.Opcode = (byte)opcode;
            _header.EventDescriptor.Level = (byte)level;
            _header.EventDescriptor.Keyword = keyword;
            _trimStringNullTerminator = trimStringNullTerminator;

            Header = new EventHeaderView(this);
        }

        /// <summary>
        /// Provides access to the EventHeader that will be packed into the faked record.
        /// </summary>
        public EventHeaderView Header { get; }

        internal ushort HeaderFlags
        {
            get { return _header.Flags; }
            set { _header.Flags = value; }
        }

        /// <summary>Adds a property with an ANSI string to the record.</summary>
        /// <remarks>
        /// The encoding is decided when the record is packed, from the property's out-type:
        /// the machine's ANSI code page normally, UTF-8 where the schema says <c>win:UTF8</c>
        /// or <c>win:Json</c>.
        /// </remarks>
        public void AddAnsiString(string name, string value)
        {
            _properties.Add(PropertyThunk.AnsiString(name, value ?? string.Empty));
        }

        /// <summary>Adds a property with a unicode string to the record.</summary>
        public void AddUnicodeString(string name, string value)
        {
            value = value ?? string.Empty;
            var bytes = new byte[(value.Length * 2) + 2];

            for (int i = 0; i < value.Length; i++)
            {
                bytes[i * 2] = (byte)value[i];
                bytes[(i * 2) + 1] = (byte)(value[i] >> 8);
            }

            _properties.Add(new PropertyThunk(name, bytes, TdhInType.UnicodeString));
        }

        /// <summary>
        /// Adds a fixed-width property to the record.
        /// </summary>
        /// <remarks>
        /// Covers the integral types, whose CLR type determines the in-type unambiguously.
        /// In-types that share a CLR representation with an integer — POINTER, FILETIME,
        /// HEXINT32 and HEXINT64 — have their own adders, because the in-type cannot be
        /// inferred from the value.
        /// </remarks>
        public void AddValue<T>(string name, T value)
        {
            object? boxed = value;

            switch (boxed)
            {
                case sbyte v:
                    Add(name, new[] { unchecked((byte)v) }, TdhInType.Int8);
                    return;
                case byte v:
                    Add(name, new[] { v }, TdhInType.UInt8);
                    return;
                case short v:
                    Add(name, BitConverter.GetBytes(v), TdhInType.Int16);
                    return;
                case ushort v:
                    Add(name, BitConverter.GetBytes(v), TdhInType.UInt16);
                    return;
                case int v:
                    Add(name, BitConverter.GetBytes(v), TdhInType.Int32);
                    return;
                case uint v:
                    Add(name, BitConverter.GetBytes(v), TdhInType.UInt32);
                    return;
                case long v:
                    Add(name, BitConverter.GetBytes(v), TdhInType.Int64);
                    return;
                case ulong v:
                    Add(name, BitConverter.GetBytes(v), TdhInType.UInt64);
                    return;
                case float v:
                    Add(name, BitConverter.GetBytes(v), TdhInType.Float);
                    return;
                case double v:
                    Add(name, BitConverter.GetBytes(v), TdhInType.Double);
                    return;
                case Guid v:
                    Add(name, v.ToByteArray(), TdhInType.Guid);
                    return;
                default:
                    throw new ArgumentException("Add value does not support type " + typeof(T));
            }
        }

        /// <summary>Adds a BOOLEAN property, which ETW encodes as four bytes.</summary>
        public void AddBoolean(string name, bool value)
        {
            Add(name, BitConverter.GetBytes(value ? 1 : 0), TdhInType.Boolean);
        }

        /// <summary>Adds a GUID property.</summary>
        public void AddGuid(string name, Guid value)
        {
            Add(name, value.ToByteArray(), TdhInType.Guid);
        }

        /// <summary>
        /// Adds a POINTER property.
        /// </summary>
        /// <remarks>
        /// The width of a pointer property is a property of the event source rather than of
        /// the value, so it is resolved when the record is packed, from the same header flags
        /// the reader consults. Set <see cref="Header"/>.Flags before packing to build a
        /// record from a 32-bit source.
        /// </remarks>
        public void AddPointer(string name, ulong value)
        {
            _properties.Add(PropertyThunk.Pointer(name, value));
        }

        /// <summary>Adds a HEXINT32 property.</summary>
        public void AddHexInt32(string name, uint value)
        {
            Add(name, BitConverter.GetBytes(value), TdhInType.HexInt32);
        }

        /// <summary>Adds a HEXINT64 property.</summary>
        public void AddHexInt64(string name, ulong value)
        {
            Add(name, BitConverter.GetBytes(value), TdhInType.HexInt64);
        }

        /// <summary>Adds a FILETIME property.</summary>
        public void AddFileTime(string name, DateTime value)
        {
            Add(name, BitConverter.GetBytes(value.ToFileTimeUtc()), TdhInType.FileTime);
        }

        /// <summary>Adds a FILETIME property from a raw FILETIME value.</summary>
        public void AddFileTime(string name, long value)
        {
            Add(name, BitConverter.GetBytes(value), TdhInType.FileTime);
        }

        /// <summary>Adds a SYSTEMTIME property.</summary>
        public void AddSystemTime(string name, DateTime value)
        {
            var bytes = new byte[16];

            WriteUInt16(bytes, 0, (ushort)value.Year);
            WriteUInt16(bytes, 2, (ushort)value.Month);
            WriteUInt16(bytes, 4, (ushort)value.DayOfWeek);
            WriteUInt16(bytes, 6, (ushort)value.Day);
            WriteUInt16(bytes, 8, (ushort)value.Hour);
            WriteUInt16(bytes, 10, (ushort)value.Minute);
            WriteUInt16(bytes, 12, (ushort)value.Second);
            WriteUInt16(bytes, 14, (ushort)value.Millisecond);

            Add(name, bytes, TdhInType.SystemTime);
        }

        /// <summary>
        /// Adds a SID property from its binary form.
        /// </summary>
        /// <remarks>
        /// A SID is variable width, and the reader sizes it from the sub-authority count in
        /// its second byte, so the value must be a well-formed binary SID:
        /// revision, sub-authority count, six bytes of identifier authority, then four bytes
        /// per sub-authority. <c>SecurityIdentifier.GetBinaryForm</c> produces this layout.
        /// </remarks>
        public void AddSid(string name, byte[] value)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }

            if (value.Length < 8 || value.Length != 8 + (value[1] * 4))
            {
                throw new ArgumentException(
                    "Value is not a well-formed binary SID for property " + name +
                    ": length " + value.Length + " does not match a sub-authority count of " + value[1]);
            }

            Add(name, (byte[])value.Clone(), TdhInType.Sid);
        }

        /// <summary>Adds a BINARY property.</summary>
        public void AddBinary(string name, byte[] value)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }

            Add(name, (byte[])value.Clone(), TdhInType.Binary);
        }

        /// <summary>Adds a container ID extended data item.</summary>
        public void AddContainerId(Guid containerId)
        {
            _extendedData.AddContainerId(containerId);
        }

        /// <summary>Adds a process start key extended data item.</summary>
        public void AddProcessStartKey(ulong processStartKey)
        {
            _extendedData.AddProcessStartKey(processStartKey);
        }

        /// <summary>
        /// Packs the event properties into an EVENT_RECORD.
        /// </summary>
        /// <exception cref="ArgumentException">Not every schema property was supplied.</exception>
        public SynthRecord Pack()
        {
            return Pack(requireComplete: true);
        }

        /// <summary>
        /// Packs the event properties into an EVENT_RECORD, tolerating properties the caller
        /// never supplied.
        /// </summary>
        public SynthRecord PackIncomplete()
        {
            return Pack(requireComplete: false);
        }

        public void Dispose()
        {
        }

        private void Add(string name, byte[] bytes, TdhInType inType)
        {
            _properties.Add(new PropertyThunk(name, bytes, inType));
        }

        private static void WriteUInt16(byte[] bytes, int offset, ushort value)
        {
            bytes[offset] = (byte)value;
            bytes[offset + 1] = (byte)(value >> 8);
        }

        private SynthRecord Pack(bool requireComplete)
        {
            // The schema is resolved from a stub record carrying only the header, which is
            // all TDH needs to identify the event.
            using (var stub = new SynthRecord(_header, null!, null!))
            using (var cache = new SchemaCache())
            {
                SchemaEntry schema = cache.Get(stub.Record);

                if (schema.Status != NativeConstants.ERROR_SUCCESS)
                {
                    throw new CouldNotFindSchema(
                        ErrorMessages.StatusAndRecordContext(
                            schema.Status, _header.ProviderId, _header.EventDescriptor.Id));
                }

                var payload = new List<byte>();
                var unfilled = new List<string>();
                var blob = (byte*)schema.Blob;
                PropertyTable table = schema.Table!;

                int pointerSize = SchemaCache.PointerSizeFor(stub.Record);
                int bytesToTrim = 0;

                for (int i = 0; i < table.Count; i++)
                {
                    bytesToTrim = 0;

                    string name = new string((char*)(blob + table.NameOffsets[i]), 0, table.NameLengths[i]);
                    int found = IndexOf(name);

                    if (found < 0)
                    {
                        unfilled.Add(name);
                        payload.AddRange(new byte[FillWidth((TdhInType)table.InTypes[i], name, pointerSize)]);
                        continue;
                    }

                    PropertyThunk thunk = _properties[found];

                    if (thunk.InType != (TdhInType)table.InTypes[i])
                    {
                        throw new ArgumentException(
                            "Invalid property type given for property " + name +
                            " Expected: " + (TdhInType)table.InTypes[i] +
                            " Received: " + thunk.InType);
                    }

                    byte[] bytes = thunk.BytesFor(pointerSize, table.OutTypes[i]);
                    int terminator = TerminatorWidth(thunk.InType);

                    if (terminator > 0)
                    {
                        if (SchemaDeclaresStringLength(table, i))
                        {
                            // The schema sizes this property, either statically or from
                            // another property, so the reader consumes exactly that many
                            // characters and never sees a terminator. Emitting one would
                            // shift every later property.
                            int units = (bytes.Length - terminator) / terminator;
                            RequireDeclaredLength(table, blob, i, name, units);

                            var sized = new byte[bytes.Length - terminator];
                            Array.Copy(bytes, sized, sized.Length);
                            bytes = sized;
                        }
                        else
                        {
                            // A trailing NUL-terminated string may have had its terminator
                            // dropped by ETW, so remember how much could be trimmed if this
                            // turns out to be the last property.
                            bytesToTrim = terminator;
                        }
                    }
                    else if (thunk.InType == TdhInType.Binary && SchemaDeclaresStringLength(table, i))
                    {
                        // A BINARY property carries no length of its own: the reader takes its
                        // width from the schema and ignores the value. Supplying a different
                        // number of bytes therefore misplaces every later property instead of
                        // failing, so it is rejected here.
                        RequireDeclaredLength(table, blob, i, name, bytes.Length);
                    }

                    payload.AddRange(bytes);
                }

                if (requireComplete && unfilled.Count > 0)
                {
                    throw new ArgumentException(
                        "Not all the properties of the event were filled: " + string.Join(" ", unfilled.ToArray()));
                }

                if (_trimStringNullTerminator && bytesToTrim > 0)
                {
                    payload.RemoveRange(payload.Count - bytesToTrim, bytesToTrim);
                }

                return new SynthRecord(_header, payload.ToArray(), _extendedData);
            }
        }

        /// <summary>
        /// Width of the terminator a string adder appends, or zero for other in-types.
        /// </summary>
        private static int TerminatorWidth(TdhInType inType)
        {
            switch (inType)
            {
                case TdhInType.UnicodeString: return 2;
                case TdhInType.AnsiString: return 1;
                default: return 0;
            }
        }

        /// <summary>
        /// Whether the schema sizes a string property, either with a static length or by
        /// reference to another property.
        /// </summary>
        private static bool SchemaDeclaresStringLength(PropertyTable table, int index)
        {
            if ((table.Flags[index] & NativeConstants.PropertyParamLength) != 0)
            {
                return true;
            }

            return table.Lengths[index] != 0;
        }

        /// <summary>
        /// Verifies that a schema-sized string is exactly as long as the schema says it is.
        /// A mismatch would decode as truncated text and misplace every later property, so
        /// it is reported at pack time rather than left for the assertion to puzzle over.
        /// </summary>
        private void RequireDeclaredLength(PropertyTable table, byte* blob, int index, string name, int units)
        {
            int declared;

            if ((table.Flags[index] & NativeConstants.PropertyParamLength) != 0)
            {
                int lengthIndex = table.Lengths[index];

                if (lengthIndex >= index)
                {
                    return;
                }

                string lengthName = new string(
                    (char*)(blob + table.NameOffsets[lengthIndex]), 0, table.NameLengths[lengthIndex]);

                int lengthProperty = IndexOf(lengthName);

                if (lengthProperty < 0 || !TryReadUnsigned(_properties[lengthProperty].Bytes, out ulong supplied))
                {
                    // The length property was left unfilled, so it pads to zero and the
                    // reader sees an empty string. PackIncomplete callers have opted into
                    // that; requireComplete callers are already told about the gap.
                    return;
                }

                if (supplied == (ulong)units)
                {
                    return;
                }

                throw new ArgumentException(
                    "Property " + name + " is " + units + " long but " + lengthName +
                    ", which the schema uses to size it, was given " + supplied + ".");
            }

            declared = table.Lengths[index];

            if (declared != units)
            {
                throw new ArgumentException(
                    "Property " + name + " is declared as " + declared +
                    " long by the schema but was given a value of length " + units + ".");
            }
        }

        private static bool TryReadUnsigned(byte[] bytes, out ulong value)
        {
            value = 0;

            switch (bytes.Length)
            {
                case 1:
                    value = bytes[0];
                    return true;
                case 2:
                    value = BitConverter.ToUInt16(bytes, 0);
                    return true;
                case 4:
                    value = BitConverter.ToUInt32(bytes, 0);
                    return true;
                case 8:
                    value = BitConverter.ToUInt64(bytes, 0);
                    return true;
                default:
                    return false;
            }
        }

        private int IndexOf(string name)
        {
            for (int i = 0; i < _properties.Count; i++)
            {
                if (string.Equals(_properties[i].Name, name, StringComparison.Ordinal))
                {
                    return i;
                }
            }

            return -1;
        }

        /// <summary>
        /// How much padding an unfilled property contributes. Port of
        /// krabs::testing::details::how_many_bytes_to_fill, which pads by the in-type's
        /// natural width rather than by the schema's declared length.
        /// </summary>
        /// <remarks>
        /// A POINTER is as wide as the record says it is, not as wide as a pointer in the
        /// process running the test: padding by the latter would leave a 32-bit record four
        /// bytes long at every unfilled pointer and misplace every property after it.
        /// </remarks>
        private static int FillWidth(TdhInType inType, string name, int pointerSize)
        {
            switch (inType)
            {
                case TdhInType.UnicodeString: return 2;
                case TdhInType.AnsiString: return 1;
                case TdhInType.Int8: return 1;
                case TdhInType.UInt8: return 1;
                case TdhInType.Int16: return 2;
                case TdhInType.UInt16: return 2;
                case TdhInType.Int32: return 4;
                case TdhInType.UInt32: return 4;
                case TdhInType.Int64: return 8;
                case TdhInType.UInt64: return 8;
                case TdhInType.Float: return 4;
                case TdhInType.Double: return 8;
                case TdhInType.Boolean: return 4;
                case TdhInType.Binary: return 1;
                case TdhInType.Guid: return 16;
                case TdhInType.Pointer: return pointerSize;
                case TdhInType.FileTime: return 8;
                case TdhInType.SystemTime: return 16;

                // A zeroed SID declares no sub-authorities, so the reader sizes it at the
                // fixed Revision(1) SubAuthorityCount(1) IdentifierAuthority(6) header
                // whatever the record's pointer width. krabs pads sizeof(PSID) here, which
                // is right on x64 by coincidence and four bytes short of a 32-bit record.
                case TdhInType.Sid: return 8;
                case TdhInType.HexInt32: return 4;
                case TdhInType.HexInt64: return 8;
                default:
                    throw new ArgumentException("Unexpected fill type for property " + name + ": " + inType);
            }
        }

        private readonly struct PropertyThunk
        {
            public readonly string Name;
            public readonly byte[] Bytes;
            public readonly TdhInType InType;

            /// <summary>
            /// Value of a POINTER property, whose width is not known until the record is
            /// packed. Null for every other in-type.
            /// </summary>
            public readonly ulong? PointerValue;

            /// <summary>
            /// Text of an ANSI string property, whose encoding is not known until the record
            /// is packed. Null for every other in-type.
            /// </summary>
            public readonly string? AnsiText;

            public PropertyThunk(string name, byte[] bytes, TdhInType inType)
                : this(name, bytes, inType, null, null)
            {
            }

            private PropertyThunk(string name, byte[] bytes, TdhInType inType, ulong? pointerValue, string? ansiText)
            {
                Name = name;
                Bytes = bytes;
                InType = inType;
                PointerValue = pointerValue;
                AnsiText = ansiText;
            }

            public static PropertyThunk Pointer(string name, ulong value)
            {
                return new PropertyThunk(name, Array.Empty<byte>(), TdhInType.Pointer, value, null);
            }

            public static PropertyThunk AnsiString(string name, string value)
            {
                return new PropertyThunk(name, Array.Empty<byte>(), TdhInType.AnsiString, null, value);
            }

            /// <summary>
            /// Bytes to emit for this property at the given pointer width and out-type.
            /// </summary>
            public byte[] BytesFor(int pointerSize, ushort outType)
            {
                if (AnsiText != null)
                {
                    byte[] text = AnsiEncoding.ForOutType(outType).GetBytes(AnsiText);
                    var terminated = new byte[text.Length + 1];
                    text.CopyTo(terminated, 0);
                    return terminated;
                }

                if (PointerValue == null)
                {
                    return Bytes;
                }

                byte[] full = BitConverter.GetBytes(PointerValue.Value);

                if (pointerSize == 8)
                {
                    return full;
                }

                var truncated = new byte[pointerSize];
                Array.Copy(full, truncated, pointerSize);
                return truncated;
            }
        }
    }
}
