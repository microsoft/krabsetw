using System;
using Microsoft.O365.Security.ETW.Testing;
using Xunit;

namespace Microsoft.O365.Security.ETW.Tests
{
    /// <summary>
    /// Covers the deprecated raw provider shim that forwards to provider metadata callbacks.
    /// </summary>
    public class CompatRawProviderTests
    {
        private static readonly Guid ProviderId = Guid.Parse("c7b29795-1698-4b96-80b4-70f88da2f45a");

        [Fact]
        public void ConstructorAndSettingsForwardToTheUnderlyingProvider()
        {
#pragma warning disable CS0618
            var provider = new RawProvider(ProviderId);
#pragma warning restore CS0618

            provider.Any = 0x10;
            provider.All = 0x20;
            provider.Level = 4;
            provider.TraceFlags = TraceFlags.IncludeStackTrace | TraceFlags.IncludeProcessStartKey;

            Assert.Equal(ProviderId, provider.Underlying.Id);
            Assert.Equal(0x10ul, provider.Underlying.Any);
            Assert.Equal(0x20ul, provider.Underlying.All);
            Assert.Equal(4, provider.Underlying.Level);
            Assert.Equal(TraceFlags.IncludeStackTrace | TraceFlags.IncludeProcessStartKey, provider.TraceFlags);
            Assert.Equal(provider.TraceFlags, provider.Underlying.TraceFlags);
#pragma warning disable CS0618
            Assert.Equal(RawProvider.AllBitsSet, ulong.MaxValue);
#pragma warning restore CS0618
        }

        [Fact]
        public void EmptyProviderNameIsRejectedByTheStringConstructor()
        {
#pragma warning disable CS0618
            Assert.Throws<ArgumentException>(() => new RawProvider(string.Empty));
#pragma warning restore CS0618
        }

        [Fact]
        public void OnEventAddsAndRemovesMetadataHandlers()
        {
            var schema = EventSchema
                .Create("Contoso-Raw-Provider", ProviderId, id: 1, version: 0)
                .UInt32("Value");

#pragma warning disable CS0618
            var rawProvider = new RawProvider(ProviderId);
#pragma warning restore CS0618

            int seen = 0;
            IEventRecordMetadataDelegate handler = record =>
            {
                seen++;
                Assert.Equal(1, record.Id);
                Assert.Equal(ProviderId, record.ProviderId);
            };

            rawProvider.OnEvent += handler;

            using (EventSchema.Use(schema))
            using (var trace = new UserTrace())
            using (var proxy = new Proxy(trace))
            {
#pragma warning disable CS0618
                trace.Enable(rawProvider);
#pragma warning restore CS0618

                using (var builder = new RecordBuilder(ProviderId, id: 1, version: 0))
                {
                    builder.AddValue("Value", 42u);
                    using (SynthRecord record = builder.Pack())
                    {
                        proxy.PushEvent(record);
                    }
                }

                rawProvider.OnEvent -= handler;

                using (var builder = new RecordBuilder(ProviderId, id: 1, version: 0))
                {
                    builder.AddValue("Value", 43u);
                    using (SynthRecord record = builder.Pack())
                    {
                        proxy.PushEvent(record);
                    }
                }
            }

            Assert.Equal(1, seen);
        }
    }
}
