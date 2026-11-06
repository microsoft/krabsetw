using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Microsoft.O365.Security.ETW.Interop;
using Microsoft.O365.Security.ETW.Schema;

namespace Microsoft.O365.Security.ETW.Tests
{
    /// <summary>
    /// Builds TRACE_EVENT_INFO blobs and EVENT_RECORDs by hand so schema-layer components can
    /// be tested without a live ETW session.
    /// </summary>
    /// <remarks>
    /// TDH will not produce every schema shape on demand -- structs, param-length properties
    /// and truncated payloads in particular -- and an end-to-end test cannot ask for a
    /// specific property access order. Constructing the blob directly is the only way to
    /// reach those cases deterministically and without elevation.
    /// </remarks>
    internal sealed unsafe class SchemaBlobBuilder
    {
        private const int HeaderSize = 112;
        private const int PropertyInfoSize = 24;

        private readonly List<PropertySpec> _properties = new List<PropertySpec>();

        private struct PropertySpec
        {
            public string Name;
            public uint Flags;
            public ushort InType;
            public ushort OutType;
            public ushort Length;
            public ushort Count;
        }

        public int Count
        {
            get { return _properties.Count; }
        }

        public SchemaBlobBuilder Add(string name, TdhInType inType, TdhOutType outType, ushort length, ushort count = 1, uint flags = 0)
        {
            _properties.Add(new PropertySpec
            {
                Name = name,
                Flags = flags,
                InType = (ushort)inType,
                OutType = (ushort)outType,
                Length = length,
                Count = count,
            });

            return this;
        }

        /// <summary>A property whose size is known from the schema alone.</summary>
        public SchemaBlobBuilder Fixed(string name, TdhInType inType, ushort length)
        {
            return Add(name, inType, TdhOutType.Null, length);
        }

        /// <summary>A NUL terminated string, whose size depends on the payload.</summary>
        public SchemaBlobBuilder NullTerminated(string name, TdhInType inType)
        {
            return Add(name, inType, TdhOutType.String, 0);
        }

        /// <summary>A property whose length is carried by an earlier property.</summary>
        public SchemaBlobBuilder ParamLength(string name, TdhInType inType, int lengthPropertyIndex)
        {
            return Add(
                name,
                inType,
                TdhOutType.Null,
                (ushort)lengthPropertyIndex,
                count: 1,
                flags: NativeConstants.PropertyParamLength);
        }

        /// <summary>A nested struct, which this implementation deliberately refuses to size.</summary>
        public SchemaBlobBuilder Struct(string name)
        {
            return Add(name, TdhInType.Null, TdhOutType.Null, 0, count: 1, flags: NativeConstants.PropertyStruct);
        }

        public SchemaBlob Build(int pointerSize = 8)
        {
            int count = _properties.Count;

            int nameArea = 0;
            foreach (PropertySpec property in _properties)
            {
                nameArea += (property.Name.Length + 1) * sizeof(char);
            }

            int propertiesOffset = HeaderSize;
            int namesOffset = propertiesOffset + (count * PropertyInfoSize);
            int blobSize = namesOffset + nameArea;

            IntPtr allocation = Marshal.AllocHGlobal(blobSize);
            byte* blob = (byte*)allocation;

            for (int i = 0; i < blobSize; i++)
            {
                blob[i] = 0;
            }

            var info = (TRACE_EVENT_INFO*)blob;
            info->PropertyCount = (uint)count;
            info->TopLevelPropertyCount = (uint)count;

            var properties = (EVENT_PROPERTY_INFO*)(blob + propertiesOffset);
            int nameCursor = namesOffset;

            for (int i = 0; i < count; i++)
            {
                PropertySpec spec = _properties[i];

                properties[i].Flags = spec.Flags;
                properties[i].InTypeOrStructStartIndex = spec.InType;
                properties[i].OutTypeOrNumOfStructMembers = spec.OutType;
                properties[i].LengthOrLengthPropertyIndex = spec.Length;
                properties[i].CountOrCountPropertyIndex = spec.Count;
                properties[i].NameOffset = (uint)nameCursor;

                var target = (char*)(blob + nameCursor);
                for (int c = 0; c < spec.Name.Length; c++)
                {
                    target[c] = spec.Name[c];
                }

                target[spec.Name.Length] = '\0';
                nameCursor += (spec.Name.Length + 1) * sizeof(char);
            }

            return new SchemaBlob(allocation, blobSize, new PropertyTable(info, pointerSize));
        }
    }

    internal sealed unsafe class SchemaBlob : IDisposable
    {
        private IntPtr _allocation;

        public SchemaBlob(IntPtr allocation, int blobSize, PropertyTable table)
        {
            _allocation = allocation;
            Table = table;
            Entry = new SchemaEntry(allocation, blobSize, table, null);
        }

        public PropertyTable Table { get; private set; }

        public SchemaEntry Entry { get; private set; }

        public byte* Pointer
        {
            get { return (byte*)_allocation; }
        }

        public void Dispose()
        {
            if (_allocation != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(_allocation);
                _allocation = IntPtr.Zero;
            }
        }
    }

    /// <summary>An EVENT_RECORD in unmanaged memory, so its payload pointer stays put.</summary>
    internal sealed unsafe class SyntheticRecord : IDisposable
    {
        private IntPtr _record;
        private IntPtr _payload;

        public SyntheticRecord(byte[] payload)
        {
            int length = payload == null ? 0 : payload.Length;

            _payload = Marshal.AllocHGlobal(Math.Max(length, 1));
            for (int i = 0; i < length; i++)
            {
                ((byte*)_payload)[i] = payload[i];
            }

            _record = Marshal.AllocHGlobal(sizeof(EVENT_RECORD));

            var record = (EVENT_RECORD*)_record;
            *record = default(EVENT_RECORD);
            record->UserData = _payload;
            record->UserDataLength = (ushort)length;
            record->EventHeader.Flags = NativeConstants.EVENT_HEADER_FLAG_64_BIT_HEADER;
        }

        public EVENT_RECORD* Record
        {
            get { return (EVENT_RECORD*)_record; }
        }

        public void Dispose()
        {
            if (_record != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(_record);
                _record = IntPtr.Zero;
            }

            if (_payload != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(_payload);
                _payload = IntPtr.Zero;
            }
        }
    }
}
