using System;
using Microsoft.O365.Security.ETW.Testing;
using Xunit;

namespace Microsoft.O365.Security.ETW.Tests
{
    /// <summary>
    /// Covers synthetic record and proxy guard rails that do not require a live ETW session.
    /// </summary>
    public class SynthProxyAndRecordTests
    {
        private static readonly Guid ProviderId = Guid.Parse("b8425930-b78d-4636-b3d8-cac04c5e5868");

        [Fact]
        public void ProxyConstructorsRejectNullTargetsWithTheTargetParameterName()
        {
            var userTrace = Assert.Throws<ArgumentNullException>(() => new Proxy((UserTrace)null));
            Assert.Equal("trace", userTrace.ParamName);

            var kernelTrace = Assert.Throws<ArgumentNullException>(() => new Proxy((KernelTrace)null));
            Assert.Equal("trace", kernelTrace.ParamName);

            var filter = Assert.Throws<ArgumentNullException>(() => new Proxy((EventFilter)null));
            Assert.Equal("filter", filter.ParamName);
        }

        [Fact]
        public void PushEventRejectsNullRecordsBeforeDispatch()
        {
            using (var proxy = new Proxy(new EventFilter(Filter.AnyEvent())))
            {
                var error = Assert.Throws<ArgumentNullException>(() => proxy.PushEvent(null));
                Assert.Equal("record", error.ParamName);
            }
        }

        [Fact]
        public void KernelTraceProxyRethrowsHandlerExceptionsAfterRecordingThem()
        {
            EventSchema schema = EventSchema
                .Create("Contoso-Kernel-Proxy", ProviderId, id: 3, version: 0)
                .UInt32("Value");

            using (var trace = new KernelTrace())
            {
                trace.DefaultEventRef = (in Microsoft.O365.Security.ETW.EventRecordRef record) =>
                    throw new InvalidOperationException("kernel handler failed");

                using (EventSchema.Use(schema))
                using (var builder = new RecordBuilder(ProviderId, id: 3, version: 0))
                {
                    builder.AddValue("Value", 1u);

                    using (SynthRecord record = builder.Pack())
                    using (var proxy = new Proxy(trace))
                    {
                        var error = Assert.Throws<InvalidOperationException>(() => proxy.PushEvent(record));
                        Assert.Contains("kernel handler failed", error.Message);
                    }

                    Assert.Equal(1ul, trace.UnhandledExceptions);
                }
            }
        }

        [Fact]
        public void DisposedSyntheticRecordsRejectFurtherDispatch()
        {
            EventSchema schema = EventSchema
                .Create("Contoso-Disposed", ProviderId, id: 1, version: 0)
                .UInt32("Value");

            using (EventSchema.Use(schema))
            using (var builder = new RecordBuilder(ProviderId, id: 1, version: 0))
            {
                builder.AddValue("Value", 1u);
                SynthRecord record = builder.Pack();
                record.Dispose();

                using (var proxy = new Proxy(new EventFilter(Filter.AnyEvent())))
                {
                    var error = Assert.Throws<ObjectDisposedException>(() => proxy.PushEvent(record));
                    Assert.Equal(nameof(SynthRecord), error.ObjectName);
                }
            }
        }

        [Fact]
        public void HeaderPropertiesRemainMutableUntilTheRecordIsDisposed()
        {
            EventSchema schema = EventSchema
                .Create("Contoso-Mutable-Header", ProviderId, id: 2, version: 0)
                .UInt32("Value");

            using (EventSchema.Use(schema))
            using (var builder = new RecordBuilder(ProviderId, id: 2, version: 0))
            {
                builder.AddValue("Value", 1u);

                using (SynthRecord record = builder.Pack())
                {
                    Guid provider = Guid.Parse("9865d441-622b-4021-8a6d-725a8fcff6e7");
                    record.ProviderId = provider;
                    record.Id = 9;
                    record.Version = 3;
                    record.Opcode = 4;
                    record.Flags = (ushort)EventHeaderFlags.CLASSIC_HEADER;

                    Assert.Equal(provider, record.ProviderId);
                    Assert.Equal((ushort)9, record.Id);
                    Assert.Equal((byte)3, record.Version);
                    Assert.Equal((byte)4, record.Opcode);
                    Assert.Equal((ushort)EventHeaderFlags.CLASSIC_HEADER, record.Flags);
                }
            }
        }
    }
}
