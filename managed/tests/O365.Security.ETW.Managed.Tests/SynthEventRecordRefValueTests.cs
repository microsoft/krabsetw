using System;
using System.Reflection;
using Microsoft.O365.Security.ETW;
using Microsoft.O365.Security.ETW.Interop;
using Microsoft.O365.Security.ETW.Testing;
using Xunit;

namespace Microsoft.O365.Security.ETW.Tests
{
    /// <summary>
    /// Covers allocation-free value access over synthetic payloads with less common TDH types.
    /// </summary>
    /// <remarks>
    /// The public declaration helper intentionally exposes only the common manifest shapes.
    /// These tests add raw TDH in-types through reflection so the record still flows through
    /// the normal synthetic record packer and <see cref="EventRecordRef"/> reader.
    /// </remarks>
    public class SynthEventRecordRefValueTests
    {
        private static readonly Guid ProviderId = Guid.Parse("ed35e94d-7854-4f72-b151-08bfc9c0ce4b");
        private static readonly MethodInfo AddSchemaProperty = typeof(EventSchema).GetMethod(
            "Add",
            BindingFlags.Instance | BindingFlags.NonPublic,
            null,
            new[] { typeof(string), typeof(TdhInType), typeof(ushort), typeof(uint), typeof(TdhOutType) },
            null);
        private static readonly MethodInfo AddRecordProperty = typeof(RecordBuilder).GetMethod(
            "Add",
            BindingFlags.Instance | BindingFlags.NonPublic,
            null,
            new[] { typeof(string), typeof(byte[]), typeof(TdhInType) },
            null);

        private delegate void RefAssert(in EventRecordRef record);

        [Fact]
        public void CountedUnicodeStringSkipsTheByteCountPrefix()
        {
            EventSchema schema = EventSchema.Create("Contoso-Counted-Unicode", ProviderId, id: 1, version: 0);
            AddRawSchemaProperty(schema, "Text", TdhInType.CountedString);
            schema.UInt32("Status");

            using (EventSchema.Use(schema))
            using (var builder = new RecordBuilder(ProviderId, id: 1, version: 0))
            {
                AddRawRecordProperty(builder, "Text", new byte[] { 4, 0, (byte)'o', 0, (byte)'k', 0 }, TdhInType.CountedString);
                builder.AddValue("Status", 77u);

                Push(builder.Pack(), (in EventRecordRef record) =>
                {
                    Assert.True(record.TryGetUnicodeString("Text".AsSpan(), out ReadOnlySpan<char> text));
                    Assert.Equal("ok", text.ToString());
                    Assert.True(record.TryGetUInt32("Status".AsSpan(), out uint status));
                    Assert.Equal(77u, status);
                });
            }
        }

        [Fact]
        public void CountedAnsiStringSkipsTheByteCountPrefixWithoutTerminatorTrimming()
        {
            EventSchema schema = EventSchema.Create("Contoso-Counted-Ansi", ProviderId, id: 2, version: 0);
            AddRawSchemaProperty(schema, "Text", TdhInType.CountedAnsiString);
            schema.UInt32("Status");

            using (EventSchema.Use(schema))
            using (var builder = new RecordBuilder(ProviderId, id: 2, version: 0))
            {
                AddRawRecordProperty(builder, "Text", new byte[] { 3, 0, (byte)'a', 0, (byte)'b' }, TdhInType.CountedAnsiString);
                builder.AddValue("Status", 88u);

                Push(builder.Pack(), (in EventRecordRef record) =>
                {
                    Assert.True(record.TryGetAnsiStringBytes("Text".AsSpan(), out ReadOnlySpan<byte> text));
                    Assert.Equal(new byte[] { (byte)'a', 0, (byte)'b' }, text.ToArray());
                    Assert.True(record.TryGetUInt32("Status".AsSpan(), out uint status));
                    Assert.Equal(88u, status);
                });
            }
        }

        [Fact]
        public void NullTerminatedStringDecodersTrimAllTrailingTerminators()
        {
            EventSchema schema = EventSchema
                .Create("Contoso-Terminated-Strings", ProviderId, id: 3, version: 0)
                .AnsiString("Ansi")
                .UnicodeString("Unicode");

            using (EventSchema.Use(schema))
            using (var builder = new RecordBuilder(ProviderId, id: 3, version: 0))
            {
                builder.AddAnsiString("Ansi", "narrow");
                builder.AddUnicodeString("Unicode", "wide\0");

                Push(builder.Pack(), (in EventRecordRef record) =>
                {
                    Assert.True(record.TryGetUnicodeString("Unicode".AsSpan(), out ReadOnlySpan<char> unicode));
                    Assert.Equal("wide", unicode.ToString());
                    Assert.True(record.TryGetAnsiStringBytes("Ansi".AsSpan(), out ReadOnlySpan<byte> ansi));
                    Assert.Equal("narrow", System.Text.Encoding.ASCII.GetString(ansi.ToArray()));
                });
            }
        }

        [Fact]
        public void BooleanAccessorReadsEtwBoolAndSuppliesDefaultsForMissingValues()
        {
            EventSchema schema = EventSchema
                .Create("Contoso-Booleans", ProviderId, id: 4, version: 0)
                .Boolean("TrueValue")
                .Boolean("FalseValue");

            using (EventSchema.Use(schema))
            using (var builder = new RecordBuilder(ProviderId, id: 4, version: 0))
            {
                builder.AddBoolean("TrueValue", true);
                builder.AddBoolean("FalseValue", false);

                Push(builder.Pack(), (in EventRecordRef record) =>
                {
                    Assert.True(record.TryGetBoolean("TrueValue".AsSpan(), out bool trueValue));
                    Assert.True(trueValue);
                    Assert.True(record.TryGetBoolean("FalseValue".AsSpan(), out bool falseValue));
                    Assert.False(falseValue);
                    Assert.False(record.TryGetBoolean("Missing".AsSpan(), out bool missing));
                    Assert.False(missing);
                    Assert.True(record.GetBoolean("Missing".AsSpan(), true));
                });
            }
        }

        [Fact]
        public void FixedWidthAccessorsReturnFalseWhenThePropertyIsMissing()
        {
            EventSchema schema = EventSchema
                .Create("Contoso-Missing", ProviderId, id: 5, version: 0)
                .UInt32("Present");

            using (EventSchema.Use(schema))
            using (var builder = new RecordBuilder(ProviderId, id: 5, version: 0))
            {
                builder.AddValue("Present", 1u);

                Push(builder.Pack(), (in EventRecordRef record) =>
                {
                    Assert.False(record.TryGetUInt64("Missing".AsSpan(), out ulong missing));
                    Assert.Equal(0ul, missing);
                    Assert.Equal(123ul, record.GetUInt64("Missing".AsSpan(), 123ul));
                    Assert.False(record.TryGetRaw(-1, out ReadOnlySpan<byte> negative));
                    Assert.True(negative.IsEmpty);
                    Assert.False(record.TryGetRaw(99, out ReadOnlySpan<byte> tooLarge));
                    Assert.True(tooLarge.IsEmpty);
                    Assert.Equal((byte)1, record.GetUInt8("Missing".AsSpan(), 1));
                    Assert.Equal((sbyte)-1, record.GetInt8("Missing".AsSpan(), -1));
                    Assert.Equal((ushort)2, record.GetUInt16("Missing".AsSpan(), 2));
                    Assert.Equal((short)-2, record.GetInt16("Missing".AsSpan(), -2));
                    Assert.Equal(3u, record.GetUInt32("Missing".AsSpan(), 3));
                    Assert.Equal(-3, record.GetInt32("Missing".AsSpan(), -3));
                    Assert.Equal(-4L, record.GetInt64("Missing".AsSpan(), -4));
                    Assert.Equal(Guid.Empty, record.GetGuid("Missing".AsSpan(), Guid.Empty));
                    Assert.Equal(5ul, record.GetPointer("Missing".AsSpan(), 5));
                    Assert.Equal(new byte[] { 1, 2 }, record.GetBinary("Missing".AsSpan(), new byte[] { 1, 2 }).ToArray());
                });
            }
        }

        [Fact]
        public void AccessorsReturnFalseWhenTheRecordNoLongerHasADeclaredSchemaInScope()
        {
            SynthRecord record;
            EventSchema schema = EventSchema
                .Create("Contoso-Out-Of-Scope", ProviderId, id: 6, version: 0)
                .Named("Scoped")
                .UInt32("Value");

            using (EventSchema.Use(schema))
            using (var builder = new RecordBuilder(ProviderId, id: 6, version: 0))
            {
                builder.AddValue("Value", 123u);
                record = builder.Pack();
            }

            using (var trace = new UserTrace())
            {
                Exception failure = null;
                int seen = 0;
                trace.DefaultEventRef = (in EventRecordRef read) =>
                {
                    seen++;
                    try
                    {
                        Assert.False(read.TryGetUInt32("Value".AsSpan(), out uint value));
                        Assert.Equal(0u, value);
                        Assert.False(read.TryGetUnicodeString("Value".AsSpan(), out ReadOnlySpan<char> text));
                        Assert.True(text.IsEmpty);
                        Assert.True(read.Name.IsEmpty);
                        Assert.Equal(0, read.PropertyCount);
                        Assert.Equal(DecodingSource.Max, read.DecodingSource);
                    }
                    catch (Exception ex)
                    {
                        failure ??= ex;
                    }
                };

                using (record)
                using (var proxy = new Proxy(trace))
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

        [Fact]
        public void StructFlaggedScalarIsNotReadAsAFixedWidthValue()
        {
            EventSchema schema = EventSchema.Create("Contoso-Struct-Flag", ProviderId, id: 7, version: 0);
            AddRawSchemaProperty(schema, "Value", TdhInType.UInt32, NativeConstants.PropertyStruct);

            using (EventSchema.Use(schema))
            using (var builder = new RecordBuilder(ProviderId, id: 7, version: 0))
            {
                builder.AddValue("Value", 123u);

                Push(builder.Pack(), (in EventRecordRef record) =>
                {
                    Assert.False(record.TryGetUInt32("Value".AsSpan(), out uint value));
                    Assert.Equal(0u, value);
                });
            }
        }

        private static void AddRawSchemaProperty(EventSchema schema, string name, TdhInType inType, uint flags = 0)
        {
            AddSchemaProperty.Invoke(schema, new object[] { name, inType, (ushort)0, flags, TdhOutType.Null });
        }

        private static void AddRawRecordProperty(RecordBuilder builder, string name, byte[] bytes, TdhInType inType)
        {
            AddRecordProperty.Invoke(builder, new object[] { name, bytes, inType });
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
