using System;
using System.Collections.Generic;
using Microsoft.O365.Security.ETW.Testing;
using Xunit;

namespace Microsoft.O365.Security.ETW.Tests
{
    /// <summary>
    /// Covers provider setup and filter pushdown invariants that are observable without
    /// opening an ETW session.
    /// </summary>
    public class TraceProviderAndFilterCoverageTests
    {
        private static readonly Guid ProviderId = Guid.Parse("ab2de797-7b91-4f08-b2aa-fd66f9cc9582");

        [Fact]
        public void GuidProviderStartsWithKrabsDefaults()
        {
            var provider = new Provider(ProviderId);

            Assert.Equal(ProviderId, provider.Id);
            Assert.Null(provider.Name);
            Assert.Equal(5, provider.Level);
            Assert.Equal(0UL, provider.Any);
            Assert.Equal(0UL, provider.All);
            Assert.Equal(TraceFlags.None, provider.TraceFlags);
            Assert.Empty(provider.Filters);
            Assert.False(provider.RundownEnabled);

            provider.EnableRundownEvents();

            Assert.True(provider.RundownEnabled);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public void NamedProviderRequiresAName(string name)
        {
            Assert.Throws<ArgumentException>(() => new Provider(name));
        }

        [Fact]
        public void AddFilterRejectsNull()
        {
            var provider = new Provider(ProviderId);

            Assert.Throws<ArgumentNullException>(() => provider.AddFilter(null));
        }

        [Fact]
        public void UserTraceExposesConfiguredCallbacksAndProperties()
        {
            string name = "Trace-Properties-" + Guid.NewGuid().ToString("N");
            using (var trace = new UserTrace(name))
            {
                EventRecordExceptionDelegate exception = e => { };
                EventRecordDelegate refHandler = (in EventRecordRef record) => { };
                IEventRecordDelegate compat = record => { };
                IEventRecordMetadataDelegate metadata = record => { };
                EventRecordErrorDelegate error = e => { };

                trace.DefaultUnhandledException = exception;
                trace.DefaultEventRef = refHandler;
                trace.DefaultEvent = compat;
                trace.DefaultMetadata = metadata;
                trace.DefaultError = error;

                Assert.Equal(name, trace.Name);
                Assert.Equal(0UL, trace.BuffersProcessed);
                Assert.Same(exception, trace.DefaultUnhandledException);
                Assert.Same(refHandler, trace.DefaultEventRef);
                Assert.Same(compat, trace.DefaultEvent);
                Assert.Same(metadata, trace.DefaultMetadata);
                Assert.Same(error, trace.DefaultError);
                Assert.Throws<ArgumentNullException>(() => trace.SetTraceProperties(null));
            }
        }

        [Fact]
        [Obsolete("RawProvider is covered here because UserTrace keeps the compatibility overload.")]
        public void UserTraceCompatibilityEnableWrapsRawProviders()
        {
#pragma warning disable CS0618
            using (var emptyTrace = new UserTrace())
            {
                Assert.Throws<ArgumentNullException>(() => emptyTrace.Enable((RawProvider)null));
            }

            using (var trace = new UserTrace())
            {
                var raw = new RawProvider(ProviderId);
                trace.Enable(raw);

                Assert.Equal(1, RunRawTrace(trace, raw, emittedId: 13));
            }
#pragma warning restore CS0618
        }

        [Fact]
        public void EventIdPredicatesExposeTheirPushdownIds()
        {
            var filter = new EventFilter(Filter.EventIdIs(3).Or(Filter.EventIdIs(5)));

            Assert.Equal(new ushort[] { 3, 5 }, filter.EventIds);
        }

        [Fact]
        public void NonEventIdPredicatesDeclinePushdown()
        {
            var filter = new EventFilter(Filter.EventIdIs(3).And(Filter.ProcessIdIs(1234)));

            Assert.Null(filter.EventIds);
        }

        [Fact]
        public void TooManyEventIdsDeclinePushdown()
        {
            Predicate predicate = Filter.EventIdIs(0);
            for (int i = 1; i <= 64; i++)
            {
                predicate = predicate.Or(Filter.EventIdIs(i));
            }

            var filter = new EventFilter(predicate);

            Assert.Null(filter.EventIds);
        }

        [Fact]
        public void ExplicitEventIdListIsCopiedForMatchingAndPushdown()
        {
            var ids = new List<ushort> { 7, 9 };
            var filter = new EventFilter(ids);
            ids.Clear();

            Assert.Equal(new ushort[] { 7, 9 }, filter.EventIds);
            Assert.Equal(1, Run(filter, emittedId: 7));
            Assert.Equal(0, Run(filter, emittedId: 8));
        }

        [Fact]
        public void DirectFilterReportsSchemaFailureAndSkipsHandlers()
        {
            var filter = new EventFilter(Filter.EventIdIs(11));
            int hits = 0;
            string error = null;

            filter.OnEventRef += (in EventRecordRef record) => hits++;
            filter.OnError += e => error = e.Message;

            using (SynthRecord record = BuildRecordWithoutDeclaredSchema(id: 11))
            using (var proxy = new Proxy(filter))
            {
                proxy.PushEvent(record);
            }

            Assert.Equal(0, hits);
            Assert.NotNull(error);
            Assert.Contains("provider_id=" + ProviderId.ToString("D"), error);
            Assert.Contains("event_id=11", error);
        }

        [Fact]
        public void EventFilterConstructorsValidateInputs()
        {
            Assert.Throws<ArgumentNullException>(() => new EventFilter((Predicate)null));
            Assert.Throws<ArgumentNullException>(() => new EventFilter((List<ushort>)null));
            Assert.Throws<ArgumentException>(() => new EventFilter(new List<ushort>()));
        }

        private static int Run(EventFilter filter, ushort emittedId)
        {
            int hits = 0;
            filter.OnEventRef += (in EventRecordRef record) => hits++;

            using (EventSchema.Use(Declaration(emittedId)))
            using (SynthRecord record = BuildRecord(emittedId))
            using (var proxy = new Proxy(filter))
            {
                proxy.PushEvent(record);
            }

            return hits;
        }

#pragma warning disable CS0618
        private static int RunRawTrace(UserTrace trace, RawProvider raw, ushort emittedId)
#pragma warning restore CS0618
        {
            int hits = 0;

            raw.OnEvent += record => hits++;

            using (EventSchema.Use(Declaration(emittedId)))
            using (SynthRecord record = BuildRecord(emittedId))
            using (var proxy = new Proxy(trace))
            {
                proxy.PushEvent(record);
            }

            return hits;
        }

        private static SynthRecord BuildRecordWithoutDeclaredSchema(ushort id)
        {
            IDisposable scope = EventSchema.Use(Declaration(id));
            try
            {
                return BuildRecord(id);
            }
            finally
            {
                scope.Dispose();
            }
        }

        private static SynthRecord BuildRecord(ushort id)
        {
            using (var builder = new RecordBuilder(ProviderId, id, version: 0))
            {
                builder.AddValue("Value", 1u);
                return builder.Pack();
            }
        }

        private static EventSchema Declaration(ushort id)
        {
            return EventSchema
                .Create("Krabs-Managed-Filter-Coverage", ProviderId, id, version: 0)
                .Named("Event" + id)
                .UInt32("Value");
        }
    }
}
