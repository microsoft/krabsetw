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
