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
        public void AddAnsiString(string name, string value)
        {
            byte[] text = AnsiEncoding.Current.GetBytes(value ?? string.Empty);
            var bytes = new byte[text.Length + 1];
            text.CopyTo(bytes, 0);

            _properties.Add(new PropertyThunk(name, bytes, TdhInType.AnsiString));
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
        /// Matches the C++/CLI generic, which recognises the four sizes of signed and
        /// unsigned integer and rejects everything else.
        /// </remarks>
        public void AddValue<T>(string name, T value)
        {
            object boxed = value;

            switch (boxed)
            {
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
                default:
                    throw new ArgumentException("Add value does not support type " + typeof(T));
            }
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

        private SynthRecord Pack(bool requireComplete)
        {
            // The schema is resolved from a stub record carrying only the header, which is
            // all TDH needs to identify the event.
            using (var stub = new SynthRecord(_header, null, null))
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
                PropertyTable table = schema.Table;

                int bytesToTrim = 0;

                for (int i = 0; i < table.Count; i++)
                {
                    bytesToTrim = 0;

                    string name = new string((char*)(blob + table.NameOffsets[i]), 0, table.NameLengths[i]);
                    int found = IndexOf(name);

                    if (found < 0)
                    {
                        unfilled.Add(name);
                        payload.AddRange(new byte[FillWidth((TdhInType)table.InTypes[i], name)]);
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

                    // A trailing string may have had its terminator dropped by ETW, so
                    // remember how much could be trimmed if this turns out to be the last
                    // property.
                    if (thunk.InType == TdhInType.UnicodeString)
                    {
                        bytesToTrim = 2;
                    }
                    else if (thunk.InType == TdhInType.AnsiString)
                    {
                        bytesToTrim = 1;
                    }

                    payload.AddRange(thunk.Bytes);
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
        private static int FillWidth(TdhInType inType, string name)
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
                case TdhInType.Pointer: return IntPtr.Size;
                case TdhInType.FileTime: return 8;
                case TdhInType.SystemTime: return 16;
                case TdhInType.Sid: return IntPtr.Size;
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

            public PropertyThunk(string name, byte[] bytes, TdhInType inType)
            {
                Name = name;
                Bytes = bytes;
                InType = inType;
            }
        }
    }
}
