using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Microsoft.O365.Security.ETW.Interop;

namespace Microsoft.O365.Security.ETW.Testing
{
    /// <summary>
    /// Builds the packed EVENT_HEADER_EXTENDED_DATA_ITEM array that a synthetic record
    /// carries. Port of krabs::testing::extended_data_builder.
    /// </summary>
    /// <remarks>
    /// The result is one contiguous allocation: the item array first, then each item's data,
    /// with every item's DataPtr pointed back into the tail. That matches the shape ETW
    /// delivers closely enough to test code that reads extended data.
    /// </remarks>
    internal sealed unsafe class ExtendedDataBuilder
    {
        private readonly List<KeyValuePair<ushort, byte[]>> _items = new List<KeyValuePair<ushort, byte[]>>();

        public int Count
        {
            get { return _items.Count; }
        }

        /// <summary>
        /// Adds a container id item. ETW carries it as the GUID's braceless registry-format
        /// string, one byte per character, with no terminator.
        /// </summary>
        public void AddContainerId(Guid containerId)
        {
            string text = containerId.ToString("D");
            var data = new byte[text.Length];

            for (int i = 0; i < text.Length; i++)
            {
                data[i] = (byte)text[i];
            }

            _items.Add(new KeyValuePair<ushort, byte[]>(NativeConstants.EVENT_HEADER_EXT_TYPE_CONTAINER_ID, data));
        }

        public void AddProcessStartKey(ulong processStartKey)
        {
            var data = new byte[sizeof(ulong)];

            for (int i = 0; i < data.Length; i++)
            {
                data[i] = (byte)(processStartKey >> (i * 8));
            }

            _items.Add(new KeyValuePair<ushort, byte[]>(NativeConstants.EVENT_HEADER_EXT_TYPE_PROCESS_START_KEY, data));
        }

        /// <summary>
        /// Allocates and fills the buffer. Ownership passes to the caller, which disposes it.
        /// </summary>
        public SafeHGlobalHandle? Pack()
        {
            if (_items.Count == 0)
            {
                return null;
            }

            int arraySize = sizeof(EVENT_HEADER_EXTENDED_DATA_ITEM) * _items.Count;
            int dataSize = 0;

            for (int i = 0; i < _items.Count; i++)
            {
                dataSize += _items[i].Value.Length;
            }

            var allocation = new SafeHGlobalHandle(arraySize + dataSize);

            try
            {
                IntPtr buffer = allocation.Pointer;
                var bytes = (byte*)buffer;

                for (int i = 0; i < arraySize + dataSize; i++)
                {
                    bytes[i] = 0;
                }

                var items = (EVENT_HEADER_EXTENDED_DATA_ITEM*)buffer;
                byte* data = bytes + arraySize;

                for (int i = 0; i < _items.Count; i++)
                {
                    byte[] payload = _items[i].Value;

                    items[i].ExtType = _items[i].Key;
                    items[i].DataSize = (ushort)payload.Length;
                    items[i].DataPtr = (ulong)data;

                    Marshal.Copy(payload, 0, (IntPtr)data, payload.Length);
                    data += payload.Length;
                }

                return allocation;
            }
            catch
            {
                allocation.Dispose();
                throw;
            }
        }
    }
}
