using System;
using Microsoft.O365.Security.ETW;
using Microsoft.O365.Security.ETW.Testing;
using Xunit;

namespace Microsoft.O365.Security.ETW.Tests
{
    /// <summary>
    /// Covers schema metadata and header-only values exposed through synthetic records.
    /// </summary>
    /// <remarks>
    /// These tests assert the observable contract when a declared schema omits optional TDH
    /// strings and when callers inspect the event header rather than payload properties.
    /// </remarks>
    public class SynthEventRecordRefSchemaTests
    {
        private static readonly Guid ProviderId = Guid.Parse("f7f019cc-e911-4bb3-b8ff-a7b697244590");

        private delegate void RefAssert(in EventRecordRef record);

        [Fact]
        public void HeaderPropertiesComeFromTheSyntheticEventHeader()
        {
            EventSchema schema = EventSchema
                .Create("Contoso-Headers", ProviderId, id: 7, version: 2)
                .Named("HeaderEvent")
                .UInt32("Value");

            using (EventSchema.Use(schema))
            using (var builder = new RecordBuilder(ProviderId, id: 7, version: 2, opcode: 11, level: 4, keyword: 0x8000000000000001, trimStringNullTerminator: false))
            {
                builder.Header.Flags = (ushort)EventHeaderFlags.TRACE_MESSAGE;
                builder.AddValue("Value", 123u);

                Push(builder.Pack(), (in EventRecordRef record) =>
                {
                    Assert.Equal((ushort)7, record.Id);
                    Assert.Equal((byte)11, record.Opcode);
                    Assert.Equal((byte)2, record.Version);
                    Assert.Equal((byte)4, record.Level);
                    Assert.Equal(0x8000000000000001ul, record.Keyword);
                    Assert.Equal((ushort)EventHeaderFlags.TRACE_MESSAGE, record.Flags);
                    Assert.Equal(ProviderId, record.ProviderId);
                    Assert.Equal(0u, record.ProcessId);
                    Assert.Equal(0u, record.ThreadId);
                    Assert.Equal(Guid.Empty, record.ActivityId);
                    Assert.Equal(0, record.RawTimestamp);
                    Assert.Equal(DateTime.FromFileTimeUtc(0), record.Timestamp);
                    Assert.NotEqual(IntPtr.Zero, record.UserData);
                    Assert.Equal(record.UserDataLength, record.UserDataSpan.Length);
                    Assert.Equal(DecodingSource.WPP, record.GetEventType());
                    Assert.Equal(DecodingSource.XMLFile, record.DecodingSource);
                });
            }
        }

        [Fact]
        public void OptionalTaskAndOpcodeNamesAreEmptyWhenTheSchemaDoesNotDeclareThem()
        {
            EventSchema schema = EventSchema
                .Create("Contoso-No-Task", ProviderId, id: 8, version: 0)
                .Named("NoTaskOrOpcode")
                .UInt32("Value");

            using (EventSchema.Use(schema))
            using (var builder = new RecordBuilder(ProviderId, id: 8, version: 0))
            {
                builder.AddValue("Value", 1u);

                Push(builder.Pack(), (in EventRecordRef record) =>
                {
                    Assert.Equal("NoTaskOrOpcode", record.Name.ToString());
                    Assert.Equal("Contoso-No-Task", record.ProviderName.ToString());
                    Assert.True(record.TaskName.IsEmpty);
                    Assert.True(record.OpcodeName.IsEmpty);
                    Assert.Equal(1, record.PropertyCount);
                    Assert.Equal(0, record.IndexOf("Value".AsSpan()));
                    Assert.Equal(-1, record.IndexOf("Missing".AsSpan()));
                });
            }
        }

        [Fact]
        public void ClassicHeaderFlagClassifiesTheEventAsWbem()
        {
            EventSchema schema = EventSchema
                .Create("Contoso-Classic", ProviderId, id: 9, version: 0)
                .UInt32("Value");

            using (EventSchema.Use(schema))
            using (var builder = new RecordBuilder(ProviderId, id: 9, version: 0))
            {
                builder.Header.Flags = (ushort)EventHeaderFlags.CLASSIC_HEADER;
                builder.AddValue("Value", 1u);

                Push(builder.Pack(), (in EventRecordRef record) =>
                {
                    Assert.Equal(DecodingSource.Wbem, record.GetEventType());
                });
            }
        }

        private static void Push(SynthRecord record, RefAssert assert)
        {
            var filter = new EventFilter(Filter.AnyEvent());
            Exception failure = null;
            int seen = 0;

            filter.OnEventRef += (in EventRecordRef evt) =>
            {
                seen++;
                try
                {
                    assert(evt);
                }
                catch (Exception ex)
                {
                    failure ??= ex;
                }
            };

            using (var proxy = new Proxy(filter))
            using (record)
            {
                proxy.PushEvent(record);
            }

            Assert.Equal(1, seen);
            if (failure != null)
            {
                throw failure;
            }
        }
    }
}
