using System;
using System.Diagnostics.Tracing;
using System.Threading;
using Xunit;

namespace Microsoft.O365.Security.ETW.Tests
{
    internal sealed class TraceMergeSource : EventSource
    {
        public static readonly TraceMergeSource Log = new TraceMergeSource();

        public static Guid ProviderGuid
        {
            get { return Log.Guid; }
        }

        private TraceMergeSource()
            : base("Krabs-Managed-Test-Merge", EventSourceSettings.EtwSelfDescribingEventFormat)
        {
        }

        public void Alpha()
        {
            Write(
                "Alpha",
                new EventSourceOptions { Keywords = (EventKeywords)0x1, Level = EventLevel.Informational },
                new Payload { value = 1 });
        }

        public void Beta()
        {
            Write(
                "Beta",
                new EventSourceOptions { Keywords = (EventKeywords)0x2, Level = EventLevel.Informational },
                new Payload { value = 2 });
        }

        [EventData]
        public sealed class Payload
        {
            public int value { get; set; }
        }
    }

    /// <summary>
    /// Covers the krabs user-trace rule that multiple Provider objects for one GUID become
    /// one ETW enablement whose keyword masks are OR'd.
    /// </summary>
    [Collection("etw")]
    public class TraceUserTraceMergeCoverageTests
    {
        [Fact]
        public void ProvidersWithTheSameGuidMergeTheirAnyKeywordMasks()
        {
            var alphaSeen = new ManualResetEventSlim(false);
            var betaSeen = new ManualResetEventSlim(false);

            var first = new Provider(TraceMergeSource.ProviderGuid)
            {
                Any = 0x1,
                Level = (byte)EventLevel.Informational
            };

            first.OnEventRef += (in EventRecordRef record) =>
            {
                if ((record.Keyword & 0x1) != 0)
                {
                    alphaSeen.Set();
                }

                if ((record.Keyword & 0x2) != 0)
                {
                    betaSeen.Set();
                }
            };

            var second = new Provider(TraceMergeSource.ProviderGuid)
            {
                Any = 0x2,
                Level = (byte)EventLevel.Informational
            };

            using (alphaSeen)
            using (betaSeen)
            using (var trace = new UserTrace("Krabs-Merge-" + Guid.NewGuid().ToString("N")))
            {
                trace.Enable(first);
                trace.Enable(second);
                trace.Open();

                var processing = new Thread(trace.Start) { IsBackground = true };
                processing.Start();

                try
                {
                    DateTime deadline = DateTime.UtcNow + EtwHarness.Timeout;
                    while (DateTime.UtcNow < deadline && (!alphaSeen.IsSet || !betaSeen.IsSet))
                    {
                        TraceMergeSource.Log.Alpha();
                        TraceMergeSource.Log.Beta();
                        WaitHandle.WaitAny(new[] { alphaSeen.WaitHandle, betaSeen.WaitHandle }, TimeSpan.FromMilliseconds(250));
                    }
                }
                finally
                {
                    trace.Stop();
                    processing.Join(EtwHarness.Timeout);
                }
            }

            Assert.True(alphaSeen.IsSet, "The first provider's keyword was not enabled.");
            Assert.True(betaSeen.IsSet, "The second provider's keyword was not OR'd into the enablement.");
        }

        [Fact]
        public void EventIdOnlyFiltersCanBePushedIntoTheEtwEnablement()
        {
            int before = TraceRegistry.InUse;

            var provider = new Provider(TestEventSource.ProviderGuid) { Any = 0 };
            provider.AddFilter(new EventFilter(1));
            provider.AddFilter(new EventFilter(2));

            using (var trace = new UserTrace("Krabs-Pushdown-" + Guid.NewGuid().ToString("N")))
            {
                trace.Enable(provider);
                trace.Open();

                Assert.Equal(before + 1, TraceRegistry.InUse);
            }

            Assert.Equal(before, TraceRegistry.InUse);
        }

        [Fact]
        public void OversizedEventIdListsDeclineEtwPushdownButStillOpen()
        {
            int before = TraceRegistry.InUse;
            var ids = new System.Collections.Generic.List<ushort>();
            for (ushort i = 0; i <= 64; i++)
            {
                ids.Add(i);
            }

            var provider = new Provider(TestEventSource.ProviderGuid) { Any = 0 };
            provider.AddFilter(new EventFilter(ids));

            using (var trace = new UserTrace("Krabs-Pushdown-Large-" + Guid.NewGuid().ToString("N")))
            {
                trace.Enable(provider);
                trace.Open();

                Assert.Equal(before + 1, TraceRegistry.InUse);
            }

            Assert.Equal(before, TraceRegistry.InUse);
        }
    }
}
