using System;
using Microsoft.O365.Security.ETW.Testing;
using Xunit;

namespace Microsoft.O365.Security.ETW.Tests
{
    /// <summary>
    /// Covers the compatibility layer's DateTime accessors for FILETIME values that are not
    /// real timestamps.
    /// </summary>
    /// <remarks>
    /// A zeroed FILETIME is how providers say "no time", and it is common: Kernel-Process
    /// reports it for a process whose creation time was not available. The C++/CLI
    /// implementation hands the raw value to DateTime::FromFileTimeUtc, which accepts zero and
    /// returns 1601-01-01. Anything the port does differently changes what existing consumers
    /// see, so the boundary is worth pinning.
    /// </remarks>
    public class FileTimeBoundaryTests
    {
        private static readonly Guid KernelProcessProviderId =
            Guid.Parse("22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716");

        private static readonly DateTime FileTimeEpoch =
            new DateTime(1601, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        /// <summary>
        /// The largest FILETIME DateTime.FromFileTimeUtc accepts: DateTime.MaxValue expressed
        /// as ticks since 1601-01-01, which is 9999-12-31T23:59:59.9999999Z.
        /// </summary>
        private const long LargestRepresentableFileTime = 2650467743999999999;

        [Fact]
        public void AZeroFileTimeReadsAsTheFileTimeEpoch()
        {
            WithCreateTime(0, record =>
            {
                Assert.True(record.TryGetDateTime("CreateTime", out DateTime value));
                Assert.Equal(FileTimeEpoch, value.ToUniversalTime());
            });
        }

        [Fact]
        public void AZeroFileTimeIsNotReportedAsAMissingProperty()
        {
            WithCreateTime(0, record =>
            {
                Assert.Equal(FileTimeEpoch, record.GetDateTime("CreateTime").ToUniversalTime());
            });
        }

        /// <summary>
        /// A negative FILETIME is not a representable time. C++/CLI lets FromFileTimeUtc throw;
        /// the TryGet form must report failure rather than propagating that.
        /// </summary>
        [Fact]
        public void ANegativeFileTimeIsReportedAsUnreadable()
        {
            WithCreateTime(-1, record =>
            {
                Assert.False(record.TryGetDateTime("CreateTime", out DateTime value));
                Assert.Equal(default(DateTime), value);
            });
        }

        /// <summary>
        /// FromFileTimeUtc rejects the top of the long range as firmly as it rejects negatives:
        /// anything past 9999-12-31 has no DateTime to map to. The TryGet form must report that
        /// the same way it reports a negative, rather than throwing out of a handler.
        /// </summary>
        [Fact]
        public void AFileTimeBeyondTheDateTimeRangeIsReportedAsUnreadable()
        {
            WithCreateTime(long.MaxValue, record =>
            {
                Assert.False(record.TryGetDateTime("CreateTime", out DateTime value));
                Assert.Equal(default(DateTime), value);
            });
        }

        [Fact]
        public void OneTickPastTheLargestRepresentableFileTimeIsReportedAsUnreadable()
        {
            WithCreateTime(LargestRepresentableFileTime + 1, record =>
            {
                Assert.False(record.TryGetDateTime("CreateTime", out DateTime value));
                Assert.Equal(default(DateTime), value);
            });
        }

        /// <summary>
        /// The guard has to stop at the boundary, not before it: the largest FILETIME that maps
        /// to a DateTime is still a readable value.
        /// </summary>
        [Fact]
        public void TheLargestRepresentableFileTimeIsReadable()
        {
            WithCreateTime(LargestRepresentableFileTime, record =>
            {
                Assert.True(record.TryGetDateTime("CreateTime", out DateTime value));
                Assert.Equal(DateTime.MaxValue.Ticks, value.Ticks);
            });
        }

        private static void WithCreateTime(long fileTime, Action<IEventRecord> assert)
        {
            using (var builder = new RecordBuilder(KernelProcessProviderId, id: 1, version: 1))
            {
                builder.AddValue("ProcessID", 4321u);
                builder.AddFileTime("CreateTime", fileTime);
                builder.AddValue("ParentProcessID", 4u);
                builder.AddValue("SessionID", 0u);
                builder.AddValue("Flags", 0u);
                builder.AddUnicodeString("ImageName", @"\Device\HarddiskVolume4\Windows\System32\cmd.exe");

                var filter = new EventFilter(Filter.AnyEvent());
                Exception failure = null;
                int seen = 0;

                filter.OnEvent += record =>
                {
                    try
                    {
                        assert(record);
                        seen++;
                    }
                    catch (Exception ex)
                    {
                        failure = failure ?? ex;
                    }
                };

                new Proxy(filter).PushEvent(builder.Pack());

                if (failure != null)
                {
                    throw failure;
                }

                Assert.Equal(1, seen);
            }
        }
    }
}
