using System;
using System.Runtime.CompilerServices;
using Microsoft.O365.Security.ETW.Schema;
using Microsoft.O365.Security.ETW.Testing;
using Xunit;

namespace Microsoft.O365.Security.ETW.Tests
{
    /// <summary>
    /// Covers the last-resort release of native memory when an object is abandoned without
    /// being disposed.
    /// </summary>
    /// <remarks>
    /// Every type here allocates with <c>Marshal.AllocHGlobal</c>, which the collector does
    /// not reclaim: without a finalizer, dropping the object leaks it for the life of the
    /// process. Disposing is still the right thing to do -- a finalizer runs at a time nobody
    /// chose -- but it must not be the only thing between a consumer and an unbounded leak.
    ///
    /// Each case drops its reference inside a non-inlined helper, so no local on this frame
    /// keeps the object reachable, then forces a collection and waits for finalizers.
    /// </remarks>
    [Collection("etw")]
    public class FinalizerTests
    {
        private static readonly Guid FinalizerProviderId =
            Guid.Parse("9f3c7d18-24ab-4e5f-9d61-7b0e2c84a3f5");

        private static EventSchema Declaration()
        {
            return EventSchema
                .Create("Contoso-Finalizer-Provider", FinalizerProviderId, id: 30, version: 0)
                .Named("Abandoned")
                .UnicodeString("Message")
                .UInt32("Number");
        }

        private static void Collect()
        {
            GC.Collect();
            GC.WaitForPendingFinalizers();
            GC.Collect();
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        private static unsafe void AbandonSchemaCache()
        {
            using (EventSchema.Use(Declaration()))
            using (var builder = new RecordBuilder(FinalizerProviderId, id: 30, version: 0))
            {
                builder.AddUnicodeString("Message", "abandoned");
                builder.AddValue("Number", 1u);

                using (SynthRecord record = builder.Pack())
                {
                    // Not disposed, and unreachable once this frame returns.
                    var cache = new SchemaCache();

                    // Loading a schema is what allocates the blob the finalizer has to free.
                    SchemaEntry entry = cache.Get(record.Record);
                    Assert.Equal(0, entry.Status);
                }
            }
        }

        [Fact]
        public void AnAbandonedSchemaCacheFreesItsBlobs()
        {
            Collect();
            int before = SchemaCache.LiveBlobs;

            AbandonSchemaCache();

            Collect();

            Assert.Equal(before, SchemaCache.LiveBlobs);
        }

        [Fact]
        public unsafe void ADisposedSchemaCacheFreesItsBlobsWithoutWaitingForTheCollector()
        {
            Collect();
            int before = SchemaCache.LiveBlobs;

            using (EventSchema.Use(Declaration()))
            using (var builder = new RecordBuilder(FinalizerProviderId, id: 30, version: 0))
            {
                builder.AddUnicodeString("Message", "disposed");
                builder.AddValue("Number", 1u);

                using (SynthRecord record = builder.Pack())
                {
                    using (var cache = new SchemaCache())
                    {
                        SchemaEntry entry = cache.Get(record.Record);
                        Assert.Equal(0, entry.Status);
                        Assert.True(
                            SchemaCache.LiveBlobs > before,
                            "Loading a schema should have allocated a blob.");
                    }

                    Assert.Equal(before, SchemaCache.LiveBlobs);
                }
            }
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        private static void AbandonOpenedTrace()
        {
            var trace = new UserTrace("Krabs-Finalizer-" + Guid.NewGuid().ToString("N"));
            trace.Enable(new Provider(TestTraceLoggingSource.ProviderGuid) { Any = 0 });

            // Opened, never stopped, never disposed: the registration, the session and the
            // logger name are all live, and only the finalizer can release them.
            trace.Open();
        }

        [Fact]
        public void AnAbandonedTraceReleasesItsRegistration()
        {
            Collect();
            int before = TraceRegistry.InUse;

            AbandonOpenedTrace();

            Collect();

            Assert.Equal(before, TraceRegistry.InUse);
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        private static void AbandonSynthRecord()
        {
            using (EventSchema.Use(Declaration()))
            using (var builder = new RecordBuilder(FinalizerProviderId, id: 30, version: 0))
            {
                builder.AddUnicodeString("Message", "abandoned");
                builder.AddValue("Number", 1u);

                // Packed and dropped without being disposed.
                builder.Pack();
            }
        }

        /// <summary>
        /// A record's finalizer has to run without faulting. There is no counter to check, so
        /// the assertion is that finalization completes and records still work afterwards --
        /// a double free or a bad pointer here would take the process down, not fail a test.
        /// </summary>
        [Fact]
        public unsafe void AnAbandonedSynthRecordFinalizesCleanly()
        {
            AbandonSynthRecord();

            Collect();

            using (EventSchema.Use(Declaration()))
            using (var builder = new RecordBuilder(FinalizerProviderId, id: 30, version: 0))
            {
                builder.AddUnicodeString("Message", "after");
                builder.AddValue("Number", 2u);

                using (SynthRecord record = builder.Pack())
                {
                    Assert.True(record.Record != null);
                }
            }
        }
    }
}
