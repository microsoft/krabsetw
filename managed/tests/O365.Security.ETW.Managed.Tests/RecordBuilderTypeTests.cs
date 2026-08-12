using System;
using Microsoft.O365.Security.ETW.Testing;
using Xunit;

namespace Microsoft.O365.Security.ETW.Tests
{
    /// <summary>
    /// Covers the property in-types <see cref="RecordBuilder"/> can supply.
    /// </summary>
    /// <remarks>
    /// <see cref="RecordBuilder"/> validates the in-type of every property it is given
    /// against the machine's schema, so an event carrying a POINTER, GUID, FILETIME or SID
    /// property could not be built at all until this file's adders existed: since properties
    /// are laid out sequentially, one unsupported type part-way through a schema prevents
    /// everything after it from being addressed.
    ///
    /// The fixtures are in-box providers chosen for the in-types they declare. SMBClient's
    /// OpenHandleStateTransition carries POINTER, UINT64 and GUID ahead of its strings;
    /// Kernel-Process ProcessStart carries FILETIME, and its later versions a SID.
    /// </remarks>
    public class RecordBuilderTypeTests
    {
        private static readonly Guid SmbClientProviderId = Guid.Parse("988C59C5-0A1C-45B6-A555-0C62276E327D");
        private static readonly Guid KernelProcessProviderId = Guid.Parse("22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716");

        /// <summary>
        /// Declared rather than in-box: no registered provider is known to place a POINTER
        /// ahead of another property in an event a 32-bit process emits.
        /// </summary>
        private static readonly Guid PointerProviderId = Guid.Parse("4a1a7d2c-5f9e-4a2b-8d3c-1e6f7b8c9d02");

        private delegate void RefAssert(in EventRecordRef record);

        [Fact]
        public void PointerAndGuidPropertiesRoundTrip()
        {
            var createGuid = Guid.Parse("5751c831-673d-4c9c-a29f-6cc865ed998f");

            WithSmbRecord(
                createGuid,
                objectAddress: 0xFFFFAB0012345678,
                (in EventRecordRef record) =>
                {
                    Assert.True(record.TryGetPointer("Object".AsSpan(), out ulong pointer));
                    Assert.Equal(0xFFFFAB0012345678, pointer);

                    Assert.True(record.TryGetGuid("CreateGUID".AsSpan(), out Guid guid));
                    Assert.Equal(createGuid, guid);
                });
        }

        [Fact]
        public void PropertiesAfterAPointerAreStillAddressable()
        {
            WithSmbRecord(
                Guid.NewGuid(),
                objectAddress: 1,
                (in EventRecordRef record) =>
                {
                    Assert.True(record.TryGetUnicodeString("ShareName".AsSpan(), out ReadOnlySpan<char> share));
                    Assert.Equal(@"\\server\IPC$", share.ToString());

                    Assert.True(record.TryGetUnicodeString("ObjectName".AsSpan(), out ReadOnlySpan<char> pipe));
                    Assert.Equal(@"\atsvc", pipe.ToString());
                });
        }

        [Fact]
        public void FileTimeRoundTripsThroughTheAllocatingSurface()
        {
            var createTime = new DateTime(2024, 3, 1, 12, 30, 45, DateTimeKind.Utc);

            WithProcessStartRecord(
                createTime,
                record =>
                {
                    Assert.Equal(createTime, record.GetDateTime("CreateTime").ToUniversalTime());
                    Assert.Equal(4321u, record.GetUInt32("ProcessID"));
                    Assert.Equal(@"\Device\HarddiskVolume4\Windows\System32\cmd.exe", record.GetUnicodeString("ImageName"));
                });
        }

        [Fact]
        public void SidPropertiesRoundTrip()
        {
            // S-1-5-32-544 (BUILTIN\Administrators): revision, sub-authority count,
            // 6-byte identifier authority, then the sub-authorities.
            byte[] sid =
            {
                0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
                0x20, 0x00, 0x00, 0x00,
                0x20, 0x02, 0x00, 0x00,
            };

            using (var builder = new RecordBuilder(KernelProcessProviderId, id: 1, version: 3))
            {
                builder.AddValue("ProcessID", 4321u);
                builder.AddValue("ProcessSequenceNumber", 7ul);
                builder.AddFileTime("CreateTime", DateTime.UtcNow);
                builder.AddValue("ParentProcessID", 4u);
                builder.AddValue("ParentProcessSequenceNumber", 1ul);
                builder.AddValue("SessionID", 0u);
                builder.AddValue("Flags", 0u);
                builder.AddValue("ProcessTokenElevationType", 1u);
                builder.AddValue("ProcessTokenIsElevated", 0u);
                builder.AddSid("MandatoryLabel", sid);
                builder.AddUnicodeString("ImageName", @"\Device\HarddiskVolume4\Windows\System32\cmd.exe");
                builder.AddValue("ImageChecksum", 0u);
                builder.AddValue("TimeDateStamp", 0u);
                builder.AddUnicodeString("PackageFullName", string.Empty);
                builder.AddUnicodeString("PackageRelativeAppId", string.Empty);

                Push(
                    builder.Pack(),
                    null,
                    record =>
                    {
                        // The property after the SID proves the variable-width value was
                        // sized correctly.
                        Assert.Equal(@"\Device\HarddiskVolume4\Windows\System32\cmd.exe", record.GetUnicodeString("ImageName"));
                    });
            }
        }

        [Fact]
        public void AddValueCoversTheSingleByteIntegers()
        {
            var builder = new RecordBuilder(SmbClientProviderId, id: 30603, version: 0);

            using (builder)
            {
                // Not part of this schema; the point is only that the types are accepted
                // rather than rejected outright by AddValue.
                builder.AddValue("SomeByte", (byte)1);
                builder.AddValue("SomeSByte", (sbyte)-1);
            }
        }

        [Fact]
        public void AddValueStillRejectsUnsupportedTypes()
        {
            using (var builder = new RecordBuilder(SmbClientProviderId, id: 30603, version: 0))
            {
                Assert.Throws<ArgumentException>(() => builder.AddValue("Whatever", DateTime.UtcNow));
            }
        }

        [Fact]
        public void MismatchedInTypeIsStillRejected()
        {
            using (var builder = new RecordBuilder(SmbClientProviderId, id: 30603, version: 0))
            {
                builder.AddValue("Object", 1ul);

                var error = Assert.Throws<ArgumentException>(() => builder.PackIncomplete());
                Assert.Contains("Expected: Pointer", error.Message);
            }
        }

        /// <summary>
        /// An unfilled property pads to the width the reader will consume. For a POINTER
        /// that width comes from the record's header flags, not from the width of a pointer
        /// in the process running the test, so a record built from a 32-bit source must pad
        /// four bytes even on x64.
        /// </summary>
        [Fact]
        public void AnUnfilledPointerPadsToTheRecordsPointerWidth()
        {
            var schema = EventSchema
                .Create("Contoso-Pointer-Provider", PointerProviderId, id: 9, version: 0)
                .Pointer("Handle")
                .UInt32("Status");

            using (EventSchema.Use(schema))
            using (var builder = new RecordBuilder(PointerProviderId, id: 9, version: 0))
            {
                builder.Header.Flags = (ushort)EventHeaderFlags.HEADER_32_BIT;
                builder.AddValue("Status", 7u);

                Push(
                    builder.PackIncomplete(),
                    (in EventRecordRef record) =>
                    {
                        Assert.True(record.TryGetPointer("Handle".AsSpan(), out ulong handle));
                        Assert.Equal(0ul, handle);

                        Assert.True(record.TryGetUInt32("Status".AsSpan(), out uint status));
                        Assert.Equal(7u, status);
                    },
                    null);
            }
        }

        /// <summary>
        /// A trace resolves each schema once and reuses it, but a POINTER property's width --
        /// and therefore the offset of everything after it -- comes from the emitting process.
        /// The same event from a WoW64 and a native process must not share one set of offsets,
        /// or whichever arrives second is decoded four bytes out with no error to show for it.
        /// </summary>
        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public void TheSameEventFromBothPointerWidthsDecodesWithItsOwnOffsets(bool thirtyTwoBitFirst)
        {
            var schema = EventSchema
                .Create("Contoso-Pointer-Provider", PointerProviderId, id: 10, version: 0)
                .Pointer("Handle")
                .UInt32("Status");

            using (EventSchema.Use(schema))
            using (var proxy = new Proxy(AssertingFilter(out Func<Exception> failure, out Func<int> seen)))
            {
                if (thirtyTwoBitFirst)
                {
                    proxy.PushEvent(PointerRecord(pointerSize: 4, handle: 0x12345678, status: 7));
                    proxy.PushEvent(PointerRecord(pointerSize: 8, handle: 0xFFFFAB0012345678, status: 9));
                }
                else
                {
                    proxy.PushEvent(PointerRecord(pointerSize: 8, handle: 0xFFFFAB0012345678, status: 9));
                    proxy.PushEvent(PointerRecord(pointerSize: 4, handle: 0x12345678, status: 7));
                }

                Assert.Equal(2, seen());

                if (failure() != null)
                {
                    throw failure();
                }
            }
        }

        /// <summary>
        /// Builds a record whose Status is derived from its Handle, so a Status read at the
        /// wrong offset is detected rather than coincidentally matching.
        /// </summary>
        private static SynthRecord PointerRecord(int pointerSize, ulong handle, uint status)
        {
            using (var builder = new RecordBuilder(PointerProviderId, id: 10, version: 0))
            {
                if (pointerSize == 4)
                {
                    builder.Header.Flags = (ushort)EventHeaderFlags.HEADER_32_BIT;
                }

                builder.AddPointer("Handle", handle);
                builder.AddValue("Status", status);
                return builder.Pack();
            }
        }

        /// <summary>
        /// A filter asserting that every record it sees reports the Handle and Status it was
        /// built with, whatever pointer width it came from.
        /// </summary>
        private static EventFilter AssertingFilter(out Func<Exception> failure, out Func<int> seen)
        {
            var filter = new EventFilter(Filter.AnyEvent());
            Exception caught = null;
            int count = 0;

            filter.OnEventRef += (in EventRecordRef record) =>
            {
                try
                {
                    bool thirtyTwoBit = (record.Flags & (ushort)EventHeaderFlags.HEADER_32_BIT) != 0;

                    Assert.True(record.TryGetPointer("Handle".AsSpan(), out ulong handle));
                    Assert.Equal(thirtyTwoBit ? 0x12345678ul : 0xFFFFAB0012345678, handle);

                    Assert.True(record.TryGetUInt32("Status".AsSpan(), out uint status));
                    Assert.Equal(thirtyTwoBit ? 7u : 9u, status);

                    count++;
                }
                catch (Exception ex)
                {
                    caught = caught ?? ex;
                }
            };

            failure = () => caught;
            seen = () => count;
            return filter;
        }

        private static void WithSmbRecord(Guid createGuid, ulong objectAddress, RefAssert refAssert)
        {
            using (var builder = new RecordBuilder(SmbClientProviderId, id: 30603, version: 0))
            {
                builder.AddPointer("Object", objectAddress);
                builder.AddValue("PersistentFID", 11ul);
                builder.AddValue("VolatileFID", 12ul);
                builder.AddGuid("CreateGUID", createGuid);
                builder.AddValue("OldState", ushort.MaxValue);
                builder.AddValue("NewState", (ushort)0);
                builder.AddValue("Status", 0u);
                builder.AddValue("Reason", 0u);
                builder.AddValue("ShareNameLength", (ushort)@"\\server\IPC$".Length);
                builder.AddUnicodeString("ShareName", @"\\server\IPC$");
                builder.AddValue("ObjectNameLength", (ushort)@"\atsvc".Length);
                builder.AddUnicodeString("ObjectName", @"\atsvc");
                builder.AddValue("PreviousStatus", 0u);
                builder.AddValue("PreviousReason", 0u);

                Push(builder.Pack(), refAssert, null);
            }
        }

        private static void WithProcessStartRecord(DateTime createTime, Action<IEventRecord> compatAssert)
        {
            using (var builder = new RecordBuilder(KernelProcessProviderId, id: 1, version: 1))
            {
                builder.AddValue("ProcessID", 4321u);
                builder.AddFileTime("CreateTime", createTime);
                builder.AddValue("ParentProcessID", 4u);
                builder.AddValue("SessionID", 0u);
                builder.AddValue("Flags", 0u);
                builder.AddUnicodeString("ImageName", @"\Device\HarddiskVolume4\Windows\System32\cmd.exe");

                Push(builder.Pack(), null, compatAssert);
            }
        }

        private static void Push(SynthRecord record, RefAssert refAssert, Action<IEventRecord> compatAssert)
        {
            var filter = new EventFilter(Filter.AnyEvent());
            Exception failure = null;
            int seen = 0;

            if (refAssert != null)
            {
                filter.OnEventRef += (in EventRecordRef evt) =>
                {
                    try
                    {
                        refAssert(evt);
                        seen++;
                    }
                    catch (Exception ex)
                    {
                        failure = failure ?? ex;
                    }
                };
            }

            if (compatAssert != null)
            {
                filter.OnEvent += evt =>
                {
                    try
                    {
                        compatAssert(evt);
                        seen++;
                    }
                    catch (Exception ex)
                    {
                        failure = failure ?? ex;
                    }
                };
            }

            using (var proxy = new Proxy(filter))
            using (record)
            {
                proxy.PushEvent(record);
            }

            filter.Dispose();

            if (failure != null)
            {
                throw failure;
            }

            Assert.True(seen > 0, "no handler observed the record");
        }
    }
}
