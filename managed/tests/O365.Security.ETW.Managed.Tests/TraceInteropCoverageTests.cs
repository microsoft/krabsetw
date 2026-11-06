using System;
using System.Text;
using Microsoft.O365.Security.ETW.Interop;
using Xunit;

namespace Microsoft.O365.Security.ETW.Tests
{
    /// <summary>
    /// Covers small interop helpers whose behaviour is otherwise only exercised indirectly
    /// from the hot event path.
    /// </summary>
    public unsafe class TraceInteropCoverageTests
    {
        [Fact]
        public void GuidKeysCompareTheRawGuidBytes()
        {
            Guid value = Guid.Parse("f3e1a3e5-7a2d-4cf5-9df6-1e96a56fd609");
            Guid other = Guid.Parse("7fba2a37-e9bb-47e7-84a7-b88ddf75b4fd");

            GuidKey fromValue = new GuidKey(value);
            Guid copy = value;
            GuidKey fromPointer = GuidKey.Read(&copy);

            Assert.True(fromValue.Equals(fromPointer));
            Assert.True(fromValue.Equals((object)fromPointer));
            Assert.Equal(fromValue.GetHashCode(), fromPointer.GetHashCode());
            Assert.False(fromValue.Equals(new GuidKey(other)));
            Assert.False(fromValue.Equals("not a guid key"));
        }

        [Fact]
        public void AnsiOutTypesSelectUtf8OnlyForUtf8Payloads()
        {
            Assert.True(AnsiEncoding.IsUtf8((ushort)TdhOutType.Utf8));
            Assert.True(AnsiEncoding.IsUtf8((ushort)TdhOutType.Json));
            Assert.False(AnsiEncoding.IsUtf8((ushort)TdhOutType.String));
            Assert.False(AnsiEncoding.IsUtf8((ushort)TdhOutType.Xml));

            Assert.Equal(Encoding.UTF8.WebName, AnsiEncoding.ForOutType((ushort)TdhOutType.Utf8).WebName);
            Assert.Equal(Encoding.UTF8.WebName, AnsiEncoding.ForOutType((ushort)TdhOutType.Json).WebName);
            Assert.Equal(AnsiEncoding.Current.CodePage, AnsiEncoding.ForOutType((ushort)TdhOutType.String).CodePage);
        }

        [Fact]
        public void TraceHandleRecognizesBothInvalidSentinels()
        {
            using (var zero = new TraceHandle(0))
            using (var invalid = new TraceHandle(NativeConstants.INVALID_PROCESSTRACE_HANDLE))
            {
                Assert.True(zero.IsInvalid);
                Assert.True(invalid.IsInvalid);
                Assert.Equal(NativeConstants.INVALID_PROCESSTRACE_HANDLE, invalid.Value);
            }
        }

        [Fact]
        public void DisposingInvalidTraceHandleClearsItsValueAndIsIdempotent()
        {
            var handle = new TraceHandle(NativeConstants.INVALID_PROCESSTRACE_HANDLE);

            handle.Dispose();
            handle.Dispose();

            Assert.Equal(0UL, handle.Value);
            Assert.True(handle.IsInvalid);
        }
    }
}
