using System;
using System.Runtime.InteropServices;
using Microsoft.O365.Security.ETW.Interop;
using Xunit;

namespace Microsoft.O365.Security.ETW.Tests
{
    /// <summary>
    /// Pins the interop struct layouts to values taken from the real Windows headers.
    /// </summary>
    /// <remarks>
    /// Every expected value here was produced by managed/tools/layoutprobe, which compiles
    /// against evntcons.h, evntrace.h and tdh.h and prints sizeof/offsetof. A mismatch means
    /// the managed declarations have drifted from the ABI, which corrupts events silently
    /// rather than failing loudly, so these are worth asserting explicitly.
    /// </remarks>
    public class LayoutFacts
    {
        [Fact]
        public void RunsOnX64()
        {
            // The expectations below are the x64 layouts.
            Assert.Equal(8, IntPtr.Size);
        }

        [Fact]
        public void EventRecordMatchesTheAbi()
        {
            Assert.Equal(112, Marshal.SizeOf<EVENT_RECORD>());
            Assert.Equal(80, (int)Marshal.OffsetOf<EVENT_RECORD>(nameof(EVENT_RECORD.BufferContext)));
            Assert.Equal(84, (int)Marshal.OffsetOf<EVENT_RECORD>(nameof(EVENT_RECORD.ExtendedDataCount)));
            Assert.Equal(86, (int)Marshal.OffsetOf<EVENT_RECORD>(nameof(EVENT_RECORD.UserDataLength)));
            Assert.Equal(88, (int)Marshal.OffsetOf<EVENT_RECORD>(nameof(EVENT_RECORD.ExtendedData)));
            Assert.Equal(96, (int)Marshal.OffsetOf<EVENT_RECORD>(nameof(EVENT_RECORD.UserData)));
            Assert.Equal(104, (int)Marshal.OffsetOf<EVENT_RECORD>(nameof(EVENT_RECORD.UserContext)));
        }

        [Fact]
        public void EventHeaderMatchesTheAbi()
        {
            Assert.Equal(80, Marshal.SizeOf<EVENT_HEADER>());
            Assert.Equal(24, (int)Marshal.OffsetOf<EVENT_HEADER>(nameof(EVENT_HEADER.ProviderId)));
            Assert.Equal(40, (int)Marshal.OffsetOf<EVENT_HEADER>(nameof(EVENT_HEADER.EventDescriptor)));
            Assert.Equal(64, (int)Marshal.OffsetOf<EVENT_HEADER>(nameof(EVENT_HEADER.ActivityId)));
        }

        [Fact]
        public void EventDescriptorMatchesTheAbi()
        {
            Assert.Equal(16, Marshal.SizeOf<EVENT_DESCRIPTOR>());
        }

        [Fact]
        public void ExtendedDataItemMatchesTheAbi()
        {
            Assert.Equal(16, Marshal.SizeOf<EVENT_HEADER_EXTENDED_DATA_ITEM>());
            Assert.Equal(8, (int)Marshal.OffsetOf<EVENT_HEADER_EXTENDED_DATA_ITEM>(
                nameof(EVENT_HEADER_EXTENDED_DATA_ITEM.DataPtr)));
        }

        [Fact]
        public void TraceLogfileMatchesTheAbi()
        {
            Assert.Equal(448, Marshal.SizeOf<EVENT_TRACE_LOGFILE>());
            Assert.Equal(28, (int)Marshal.OffsetOf<EVENT_TRACE_LOGFILE>(nameof(EVENT_TRACE_LOGFILE.ProcessTraceMode)));
            Assert.Equal(400, (int)Marshal.OffsetOf<EVENT_TRACE_LOGFILE>(nameof(EVENT_TRACE_LOGFILE.BufferCallback)));
            Assert.Equal(424, (int)Marshal.OffsetOf<EVENT_TRACE_LOGFILE>(nameof(EVENT_TRACE_LOGFILE.EventRecordCallback)));
            Assert.Equal(440, (int)Marshal.OffsetOf<EVENT_TRACE_LOGFILE>(nameof(EVENT_TRACE_LOGFILE.Context)));
        }

        [Fact]
        public void TracePropertiesMatchTheAbi()
        {
            Assert.Equal(48, Marshal.SizeOf<WNODE_HEADER>());
            Assert.Equal(120, Marshal.SizeOf<EVENT_TRACE_PROPERTIES>());
        }

        [Fact]
        public void EnableTraceParametersMatchTheAbi()
        {
            Assert.Equal(48, Marshal.SizeOf<ENABLE_TRACE_PARAMETERS>());
            Assert.Equal(32, (int)Marshal.OffsetOf<ENABLE_TRACE_PARAMETERS>(nameof(ENABLE_TRACE_PARAMETERS.EnableFilterDesc)));
            Assert.Equal(40, (int)Marshal.OffsetOf<ENABLE_TRACE_PARAMETERS>(nameof(ENABLE_TRACE_PARAMETERS.FilterDescCount)));
        }

        [Fact]
        public void FilterDescriptorMatchesTheAbi()
        {
            Assert.Equal(16, Marshal.SizeOf<EVENT_FILTER_DESCRIPTOR>());
        }

        [Fact]
        public void TraceEventInfoMatchesTheAbi()
        {
            // The native struct measures 136 bytes because it ends with a one-element
            // ANYSIZE_ARRAY of EVENT_PROPERTY_INFO. The managed declaration stops before that
            // array and indexes into it manually, so it stops at the array's offset.
            Assert.Equal(112, Marshal.SizeOf<TRACE_EVENT_INFO>());
            Assert.Equal(112, Microsoft.O365.Security.ETW.Schema.TraceEventInfoLayout.PropertyArrayOffset);
            Assert.Equal(136, Marshal.SizeOf<TRACE_EVENT_INFO>() + Marshal.SizeOf<EVENT_PROPERTY_INFO>());
        }

        [Fact]
        public void EventPropertyInfoMatchesTheAbi()
        {
            Assert.Equal(24, Marshal.SizeOf<EVENT_PROPERTY_INFO>());
            Assert.Equal(16, (int)Marshal.OffsetOf<EVENT_PROPERTY_INFO>(
                nameof(EVENT_PROPERTY_INFO.CountOrCountPropertyIndex)));
            Assert.Equal(18, (int)Marshal.OffsetOf<EVENT_PROPERTY_INFO>(
                nameof(EVENT_PROPERTY_INFO.LengthOrLengthPropertyIndex)));
        }
    }
}
