using System;
using System.Runtime.InteropServices;
using Microsoft.O365.Security.ETW.Interop;
using Microsoft.O365.Security.ETW.Schema;
using Xunit;

namespace Microsoft.O365.Security.ETW.Tests
{
    /// <summary>
    /// Offset resolution against a schema containing a property this implementation cannot
    /// size, which is what a caller reading properties out of order can run into.
    /// </summary>
    /// <remarks>
    /// Offsets are memoised behind a high-water mark, so reading a late property and then an
    /// early one costs a single walk rather than two. That memoisation must not become a way
    /// for a property that fails to decode to take working ones down with it: krabs resolves
    /// every offset from scratch on each access and so cannot have that problem, and the port
    /// has to behave the same.
    /// </remarks>
    public unsafe class OffsetResolverTests : IDisposable
    {
        private const int HeaderSize = 112;
        private const int PropertyInfoSize = 24;
        private const int PointerSize = 8;

        /// <summary>first (UInt32), middle (a struct, which this implementation will not size), last (UInt32).</summary>
        private readonly IntPtr _blob;
        private readonly SchemaEntry _schema;
        private readonly IntPtr _payload;
        private readonly IntPtr _record;

        public OffsetResolverTests()
        {
            const int PropertyCount = 3;
            string[] names = { "first", "middle", "last" };

            int nameArea = 0;
            foreach (string name in names)
            {
                nameArea += (name.Length + 1) * sizeof(char);
            }

            int propertiesOffset = HeaderSize;
            int namesOffset = propertiesOffset + (PropertyCount * PropertyInfoSize);
            int blobSize = namesOffset + nameArea;

            _blob = Marshal.AllocHGlobal(blobSize);
            byte* blob = (byte*)_blob;

            for (int i = 0; i < blobSize; i++)
            {
                blob[i] = 0;
            }

            var info = (TRACE_EVENT_INFO*)blob;
            info->PropertyCount = PropertyCount;
            info->TopLevelPropertyCount = PropertyCount;

            var properties = (EVENT_PROPERTY_INFO*)(blob + propertiesOffset);

            int nameCursor = namesOffset;
            for (int i = 0; i < PropertyCount; i++)
            {
                properties[i].NameOffset = (uint)nameCursor;

                var target = (char*)(blob + nameCursor);
                for (int c = 0; c < names[i].Length; c++)
                {
                    target[c] = names[i][c];
                }

                target[names[i].Length] = '\0';
                nameCursor += (names[i].Length + 1) * sizeof(char);

                properties[i].CountOrCountPropertyIndex = 1;
            }

            properties[0].InTypeOrStructStartIndex = (ushort)TdhInType.UInt32;
            properties[0].LengthOrLengthPropertyIndex = 4;

            // A struct. PropertySizer deliberately refuses these rather than reading
            // misaligned data, so the walk stops here.
            properties[1].Flags = NativeConstants.PropertyStruct;

            properties[2].InTypeOrStructStartIndex = (ushort)TdhInType.UInt32;
            properties[2].LengthOrLengthPropertyIndex = 4;

            var table = new PropertyTable(info, PointerSize);
            _schema = new SchemaEntry(_blob, blobSize, table, null);

            _payload = Marshal.AllocHGlobal(12);
            _record = Marshal.AllocHGlobal(sizeof(EVENT_RECORD));

            var record = (EVENT_RECORD*)_record;
            *record = default;
            record->UserData = _payload;
            record->UserDataLength = 12;
            record->EventHeader.Flags = NativeConstants.EVENT_HEADER_FLAG_64_BIT_HEADER;
        }

        [Fact]
        public void ResolvesOffsetsBeforeTheUndecodableProperty()
        {
            var offsets = new OffsetResolver();
            offsets.Begin((EVENT_RECORD*)_record, _schema);

            Assert.Equal(0, offsets.GetOffset(0));
            Assert.Equal(4, offsets.GetOffset(1));
        }

        [Fact]
        public void DoesNotResolveOffsetsAfterTheUndecodableProperty()
        {
            var offsets = new OffsetResolver();
            offsets.Begin((EVENT_RECORD*)_record, _schema);

            Assert.Equal(-1, offsets.GetOffset(2));
        }

        /// <summary>
        /// The out-of-order case: a caller reads a property beyond the struct, then one before
        /// it. The second read is schema-known and must still resolve.
        /// </summary>
        [Fact]
        public void ReadingPastAnUndecodablePropertyLeavesEarlierOnesReadable()
        {
            var offsets = new OffsetResolver();
            offsets.Begin((EVENT_RECORD*)_record, _schema);

            Assert.Equal(-1, offsets.GetOffset(2));

            Assert.Equal(0, offsets.GetOffset(0));
            Assert.Equal(4, offsets.GetOffset(1));
        }

        public void Dispose()
        {
            Marshal.FreeHGlobal(_blob);
            Marshal.FreeHGlobal(_payload);
            Marshal.FreeHGlobal(_record);
        }
    }
}
