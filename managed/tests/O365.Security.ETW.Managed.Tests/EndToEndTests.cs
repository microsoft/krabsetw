using System;
using System.Collections.Concurrent;
using System.Diagnostics.Tracing;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace Microsoft.O365.Security.ETW.Tests
{
    [EventSource(Name = ProviderName)]
    internal sealed class TestEventSource : EventSource
    {
        public const string ProviderName = "Krabs-Managed-Test-Provider";

        public static readonly TestEventSource Log = new TestEventSource();

        public static Guid ProviderGuid => Log.Guid;

        [Event(1, Level = EventLevel.Informational)]
        public void Interesting(string message, int number)
        {
            WriteEvent(1, message, number);
        }

        [Event(2, Level = EventLevel.Informational)]
        public void Boring(int value)
        {
            WriteEvent(2, value);
        }
    }

    /// <summary>
    /// A self-describing (TraceLogging) provider.
    /// </summary>
    /// <remarks>
    /// Manifest-based EventSource providers publish their manifest in-band rather than
    /// registering it with the system, so TDH cannot decode their payloads. That is equally
    /// true of native krabs, which also relies on TDH. Payload decoding is therefore exercised
    /// against TraceLogging events, whose schema travels with each event.
    /// </remarks>
    internal sealed class TestTraceLoggingSource : EventSource
    {
        public const string ProviderName = "Krabs-Managed-Test-Tlg";

        public static readonly TestTraceLoggingSource Log = new TestTraceLoggingSource();

        public static Guid ProviderGuid => Log.Guid;

        private TestTraceLoggingSource()
            : base(ProviderName, EventSourceSettings.EtwSelfDescribingEventFormat)
        {
        }

        public void Interesting(string message, int number)
        {
            Write("Interesting", new Payload { message = message, number = number });
        }

        public void Boring(int value)
        {
            Write("Boring", new BoringPayload { value = value });
        }

        [EventData]
        public sealed class Payload
        {
            public string message { get; set; }

            public int number { get; set; }
        }

        [EventData]
        public sealed class BoringPayload
        {
            public int value { get; set; }
        }
    }

    /// <summary>
    /// Exercises a real ETW session against a real provider.
    /// </summary>
    /// <remarks>
    /// These need an elevated process, because creating a session does. They are the only
    /// tests that prove the interop layouts, the callback thunk, the schema cache and the
    /// offset walker agree with what Windows actually delivers.
    /// </remarks>
    [Collection("etw")]
    public class EndToEndTests
    {
        private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(30);

        /// <summary>
        /// Native krabs resolves provider names through TdhEnumerateProviders, so only
        /// names registered with the system resolve. An EventSource that has never
        /// registered a manifest with the machine is not one of them.
        /// </summary>
        [Fact]
        public void ProviderNameLookupRequiresASystemRegisteredProvider()
        {
            Assert.Equal(
                new Guid("22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716"),
                Provider.GuidFromName("Microsoft-Windows-Kernel-Process"));

            var ex = Assert.Throws<ArgumentException>(
                () => Provider.GuidFromName(TestEventSource.ProviderName));

            Assert.Contains("Provider name does not exist.", ex.Message);
        }

        /// <summary>
        /// Lookup is case sensitive, matching krabs::provider_name_to_guid.
        /// </summary>
        [Fact]
        public void ProviderNameLookupIsCaseSensitive()
        {
            Assert.Throws<ArgumentException>(
                () => Provider.GuidFromName("microsoft-windows-kernel-process"));
        }

        [Fact]
        public void DeliversAndDecodesEvents()
        {
            var received = new ConcurrentQueue<Tuple<string, int>>();
            var signal = new ManualResetEventSlim();

            var filter = new EventFilter(Filter.EventNameIs("Interesting") && EtwHarness.ThisProcess);
            filter.OnEventRef += (in EventRecordRef record) =>
            {
                if (record.TryGetUnicodeString("message".AsSpan(), out ReadOnlySpan<char> message)
                    && record.TryGetInt32("number".AsSpan(), out int number))
                {
                    received.Enqueue(Tuple.Create(message.ToString(), number));
                    signal.Set();
                }
            };

            var provider = new Provider(TestTraceLoggingSource.ProviderGuid)
            {
                Any = 0
            };
            provider.AddFilter(filter);

            RunTrace(provider, signal, () => TestTraceLoggingSource.Log.Interesting("hello krabs", 42));

            Assert.True(received.TryDequeue(out Tuple<string, int> first), "No matching event was delivered.");
            Assert.Equal("hello krabs", first.Item1);
            Assert.Equal(42, first.Item2);
        }

        [Fact]
        public void PredicateRejectsNonMatchingEvents()
        {
            int matched = 0;
            int rejected = 0;
            var signal = new ManualResetEventSlim();

            // Two filters on one provider, so event id pushdown keeps both ids but each
            // filter still has to reject the other's events.
            var interesting = new EventFilter(Filter.EventIdIs(1) && EtwHarness.ThisProcess);
            interesting.OnEventRef += (in EventRecordRef record) =>
            {
                Interlocked.Increment(ref matched);
                signal.Set();
            };

            var boring = new EventFilter(Filter.EventIdIs(2) && EtwHarness.ThisProcess);
            boring.OnEventRef += (in EventRecordRef record) =>
            {
                Interlocked.Increment(ref rejected);
            };

            var provider = new Provider(TestEventSource.ProviderGuid)
            {
                Any = 0
            };
            provider.AddFilter(interesting);
            provider.AddFilter(boring);

            RunTrace(provider, signal, () =>
            {
                TestEventSource.Log.Interesting("a", 1);
                TestEventSource.Log.Boring(7);
            });

            Assert.True(matched > 0, "The event id 1 filter never fired.");
            Assert.True(rejected > 0, "The event id 2 filter never fired.");
        }

        [Fact]
        public void CompatibilityInterfaceDecodesTheSameValues()
        {
            string message = null;
            int number = 0;
            var signal = new ManualResetEventSlim();

            var filter = new EventFilter(Filter.EventNameIs("Interesting") && EtwHarness.ThisProcess);
            filter.OnEvent += record =>
            {
                message = record.GetUnicodeString("message", null);
                number = record.GetInt32("number", 0);
                signal.Set();
            };

            var provider = new Provider(TestTraceLoggingSource.ProviderGuid)
            {
                Any = 0
            };
            provider.AddFilter(filter);

            RunTrace(provider, signal, () => TestTraceLoggingSource.Log.Interesting("compat", 99));

            Assert.Equal("compat", message);
            Assert.Equal(99, number);
        }

        [Fact]
        public void StringPredicateMatchesWithoutMaterialisingTheValue()
        {
            var signal = new ManualResetEventSlim();
            int hits = 0;

            var filter = new EventFilter(
                Filter.EventNameIs("Interesting").And(UnicodeString.Is("message", "needle")) && EtwHarness.ThisProcess);

            filter.OnEventRef += (in EventRecordRef record) =>
            {
                Interlocked.Increment(ref hits);
                signal.Set();
            };

            var provider = new Provider(TestTraceLoggingSource.ProviderGuid)
            {
                Any = 0
            };
            provider.AddFilter(filter);

            RunTrace(provider, signal, () =>
            {
                TestTraceLoggingSource.Log.Interesting("haystack", 1);
                TestTraceLoggingSource.Log.Interesting("needle", 2);
            });

            Assert.True(hits > 0, "The string predicate never matched.");
        }

        [Fact]
        public void RecordIsInvalidAfterTheCallbackReturns()
        {
            IEventRecord escaped = null;
            var signal = new ManualResetEventSlim();

            var filter = new EventFilter(Filter.EventNameIs("Interesting") && EtwHarness.ThisProcess);
            filter.OnEvent += record =>
            {
                escaped = record;
                signal.Set();
            };

            var provider = new Provider(TestTraceLoggingSource.ProviderGuid)
            {
                Any = 0
            };
            provider.AddFilter(filter);

            RunTrace(provider, signal, () => TestTraceLoggingSource.Log.Interesting("escape", 1));

            Assert.NotNull(escaped);
            Assert.Throws<InvalidOperationException>(() => escaped.ProcessId);
        }

        /// <summary>
        /// TDH cannot decode manifest-based EventSource payloads, because the manifest is
        /// published in-band rather than registered with the machine. C++/CLI reports that
        /// through OnError and never invokes OnEvent; the ref surface does not need a schema
        /// for header access, so it still fires.
        /// </summary>
        [Fact]
        public void MissingSchemaRoutesCompatHandlersToOnErrorButNotSpanHandlers()
        {
            int refHits = 0;
            int compatHits = 0;
            string error = null;
            var signal = new ManualResetEventSlim();

            var filter = new EventFilter(Filter.EventIdIs(1) && EtwHarness.ThisProcess);
            filter.OnEventRef += (in EventRecordRef record) => Interlocked.Increment(ref refHits);
            filter.OnEvent += record => Interlocked.Increment(ref compatHits);
            filter.OnError += e =>
            {
                error = e.Message;
                signal.Set();
            };

            var provider = new Provider(TestEventSource.ProviderGuid)
            {
                Any = 0
            };
            provider.AddFilter(filter);

            RunTrace(provider, signal, () => TestEventSource.Log.Interesting("no schema", 1));

            Assert.True(refHits > 0, "The ref handler never fired.");
            Assert.Equal(0, compatHits);
            Assert.NotNull(error);
            Assert.Contains("status_code=", error);
            Assert.Contains("event_id=1", error);
        }

        private static void RunTrace(Provider provider, ManualResetEventSlim signal, Action emit)
        {
            EtwHarness.Run(provider, signal, emit);
        }
    }
}
