using System;
using Microsoft.O365.Security.ETW;
using Microsoft.O365.Security.ETW.Testing;
using Xunit;

namespace Microsoft.O365.Security.ETW.Tests
{
    /// <summary>
    /// Covers routing of MOF (classic/WBEM) and WPP events, which unlike manifest events
    /// carry their real provider GUID in the schema rather than the header, and so are only
    /// routed to a provider when the trace resolves that schema.
    /// </summary>
    /// <remarks>
    /// These exist because the two switches that gate that routing default to on in
    /// krabs::trace, and the C++/CLI wrapper exposed them set-only over that default. A
    /// consumer that enables a classic provider and never touches the property therefore
    /// expects its events, and turning the default around would take a working sensor
    /// silently blind rather than fail loudly.
    /// </remarks>
    public class MofWppRoutingTests
    {
        private static readonly Guid ProviderId = Guid.Parse("b6c1f2ae-6a04-4a5e-9f7d-8c3e1d0b5a42");

        [Fact]
        public void MofEventsReachTheirProviderByDefault()
        {
            Assert.Equal(1, RunProvider(EventHeaderFlags.CLASSIC_HEADER, configure: null));
        }

        [Fact]
        public void WppEventsReachTheirProviderByDefault()
        {
            Assert.Equal(1, RunProvider(EventHeaderFlags.TRACE_MESSAGE, configure: null));
        }

        [Fact]
        public void MofRoutingIsOnByDefaultAndCanBeTurnedOff()
        {
            var trace = new UserTrace();
            Assert.True(trace.MOFEventProcessingEnabled);

            Assert.Equal(0, RunProvider(
                EventHeaderFlags.CLASSIC_HEADER,
                t => t.MOFEventProcessingEnabled = false));
        }

        [Fact]
        public void WppRoutingIsOnByDefaultAndCanBeTurnedOff()
        {
            var trace = new UserTrace();
            Assert.True(trace.WPPEventProcessingEnabled);

            Assert.Equal(0, RunProvider(
                EventHeaderFlags.TRACE_MESSAGE,
                t => t.WPPEventProcessingEnabled = false));
        }

        /// <summary>
        /// A classic event that no provider claims still reaches the trace-level handler, so
        /// turning routing off narrows delivery rather than dropping the event outright.
        /// </summary>
        [Fact]
        public void AnUnroutedMofEventStillReachesTheDefaultHandler()
        {
            int defaults = 0;
            int claimed = RunProvider(
                EventHeaderFlags.CLASSIC_HEADER,
                t =>
                {
                    t.MOFEventProcessingEnabled = false;
                    t.DefaultEventRef = (in EventRecordRef record) => defaults++;
                });

            Assert.Equal(0, claimed);
            Assert.Equal(1, defaults);
        }

        private static int RunProvider(EventHeaderFlags flags, Action<UserTrace> configure)
        {
            int hits = 0;

            var provider = new Provider(ProviderId);
            provider.OnEventRef += (in EventRecordRef record) => hits++;

            using (EventSchema.Use(Declaration()))
            {
                var trace = new UserTrace();
                configure?.Invoke(trace);

                var proxy = new Proxy(trace);
                trace.Enable(provider);

                using (var builder = new RecordBuilder(ProviderId, id: 7, version: 0))
                {
                    builder.Header.Flags |= (ushort)flags;
                    builder.AddValue("ProcessId", 4321u);

                    using (SynthRecord record = builder.Pack())
                    {
                        proxy.PushEvent(record);
                    }
                }
            }

            return hits;
        }

        private static EventSchema Declaration()
        {
            return EventSchema
                .Create("Contoso-Classic-Provider", ProviderId, id: 7, version: 0)
                .Named("ClassicEvent")
                .UInt32("ProcessId");
        }
    }
}
