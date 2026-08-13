using System;
using System.Diagnostics.Tracing;
using System.Threading;
using Xunit;

namespace Microsoft.O365.Security.ETW.Tests
{
    /// <summary>
    /// A TraceLogging provider that logs an array followed by a scalar.
    /// </summary>
    /// <remarks>
    /// The trailing scalar is the assertion: an array sized wrongly moves it, so reading it
    /// back proves the array was walked correctly without needing to read the array itself.
    /// Manifest EventSource providers cannot be used for this -- their manifest is published
    /// in-band rather than registered, so TDH cannot decode their payloads at all.
    /// </remarks>
    internal sealed class TestArraySource : EventSource
    {
        public const string ProviderName = "Krabs-Managed-Test-Array";

        public static readonly TestArraySource Log = new TestArraySource();

        public static Guid ProviderGuid => Log.Guid;

        private TestArraySource()
            : base(ProviderName, EventSourceSettings.EtwSelfDescribingEventFormat)
        {
        }

        public void Sized(int[] values, int trailer)
        {
            Write("Sized", new Payload { values = values, trailer = trailer });
        }

        [EventData]
        public sealed class Payload
        {
            public int[] values { get; set; }

            public int trailer { get; set; }
        }
    }

    /// <summary>
    /// Covers array properties whose element count comes from the payload.
    /// </summary>
    [Collection("etw")]
    public class DynamicArrayCountTests
    {
        /// <summary>
        /// An empty array occupies no bytes. Sizing it as one element would move every later
        /// property, so the trailing scalar is read back to prove it did not move.
        /// </summary>
        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(3)]
        public void AnArrayOccupiesExactlyItsElements(int elements)
        {
            const int Trailer = 0x0BADCAFE;

            var values = new int[elements];
            for (int i = 0; i < elements; i++)
            {
                values[i] = i + 1;
            }

            var provider = new Provider(TestArraySource.ProviderGuid)
            {
                Any = 0
            };
            var filter = new EventFilter(Filter.EventNameIs("Sized") && EtwHarness.ThisProcess);

            using (var signal = new ManualResetEventSlim(false))
            {
                int read = 0;
                Exception failure = null;

                filter.OnEventRef += (in EventRecordRef record) =>
                {
                    try
                    {
                        if (record.TryGetInt32("trailer".AsSpan(), out int trailer))
                        {
                            read = trailer;
                            signal.Set();
                        }
                    }
                    catch (Exception ex)
                    {
                        failure = failure ?? ex;
                        signal.Set();
                    }
                };

                provider.AddFilter(filter);

                EtwHarness.Run(provider, signal, () => TestArraySource.Log.Sized(values, Trailer));

                if (failure != null)
                {
                    throw failure;
                }

                Assert.True(signal.IsSet, "No event carrying a readable trailer arrived.");
                Assert.Equal(Trailer, read);
            }
        }
    }
}
