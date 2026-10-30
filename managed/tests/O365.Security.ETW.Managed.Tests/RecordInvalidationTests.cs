using System;
using Microsoft.O365.Security.ETW.Testing;
using Xunit;

namespace Microsoft.O365.Security.ETW.Tests
{
    /// <summary>
    /// Covers the guarantee that an <see cref="IEventRecord"/> outliving its callback fails
    /// loudly rather than reading a buffer ETW has taken back.
    /// </summary>
    /// <remarks>
    /// The adapter is one instance per trace, reused for every event, so the only thing
    /// standing between a stashed reference and freed memory is that it is invalidated when
    /// the callback returns. EndToEndTests covers the normal return. This covers the path
    /// where a handler throws, which is the one that used to be held up by a try/finally
    /// inside the dispatch path and is now the caller's responsibility -- so it is the path
    /// that would regress silently if a caller ever forgot.
    /// </remarks>
    public class RecordInvalidationTests
    {
        private static readonly Guid ProviderId =
            Guid.Parse("6b2f18d4-70c3-4a91-8e5d-2fc7b0a94316");

        [Fact]
        public void RecordIsInvalidAfterAHandlerThrows()
        {
            IEventRecord escaped = null;

            var provider = new Provider(ProviderId);
            provider.OnEvent += record =>
            {
                escaped = record;
                throw new InvalidTimeZoneException("from the handler");
            };

            using (EventSchema.Use(Declaration()))
            {
                var trace = new UserTrace();
                var proxy = new Proxy(trace);

                trace.Enable(provider);

                // Proxy stands in for the ETW callback boundary, which swallows the exception
                // rather than letting it reach native code. Here it surfaces, which is what
                // lets the test observe the state left behind.
                Assert.Throws<InvalidTimeZoneException>(() => Push(proxy));
            }

            Assert.NotNull(escaped);

            // Without the caller invalidating on this path, this reads through a dangling
            // pointer instead of throwing.
            Assert.Throws<InvalidOperationException>(() => escaped.ProcessId);
        }

        [Fact]
        public void RecordIsInvalidAfterAHandlerReturns()
        {
            IEventRecord escaped = null;

            var provider = new Provider(ProviderId);
            provider.OnEvent += record => escaped = record;

            using (EventSchema.Use(Declaration()))
            {
                var trace = new UserTrace();
                var proxy = new Proxy(trace);

                trace.Enable(provider);
                Push(proxy);
            }

            Assert.NotNull(escaped);
            Assert.Throws<InvalidOperationException>(() => escaped.ProcessId);
        }

        private static void Push(Proxy proxy)
        {
            using (var builder = new RecordBuilder(ProviderId, id: 1, version: 0))
            {
                builder.AddValue("ProcessId", 4321u);

                using (SynthRecord record = builder.Pack())
                {
                    proxy.PushEvent(record);
                }
            }
        }

        private static EventSchema Declaration()
        {
            return EventSchema
                .Create("Krabs-Managed-Invalidation-Test", ProviderId, id: 1, version: 0)
                .Named("InvalidationEvent")
                .UInt32("ProcessId");
        }
    }
}
