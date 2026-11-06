using System;
using Microsoft.O365.Security.ETW.Interop;
using Microsoft.O365.Security.ETW.Kernel;
using Xunit;

namespace Microsoft.O365.Security.ETW.Tests
{
    /// <summary>
    /// Covers the LogFileMode a session actually starts with when a caller supplies none.
    /// </summary>
    /// <remarks>
    /// Regression coverage for a leak where every real-time session committed one buffer
    /// pool *per processor* instead of one for the whole session, because
    /// <c>EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING</c> was silently dropped from the default.
    /// Native krabs (<c>trace_manager::fill_trace_info</c>) only applies
    /// <c>REAL_TIME_MODE | NO_PER_PROCESSOR_BUFFERING</c> when the caller's <c>LogFileMode</c>
    /// is zero, and uses the caller's value verbatim otherwise -- this asserts the port does
    /// the same for both <see cref="UserTrace"/> and <see cref="KernelTrace"/>.
    /// </remarks>
    [Collection("etw")]
    public unsafe class TracePropertiesDefaultsTests
    {
        /// <summary>
        /// Queries a running session's LogFileMode by name, the same way <see cref="FailedOpenTeardownTests"/>
        /// queries session state: a raw properties buffer sized for the logger/log-file names
        /// ControlTrace requires even though this trace has neither.
        /// </summary>
        private static uint QueryLogFileMode(string name)
        {
            int size = sizeof(EVENT_TRACE_PROPERTIES) + ((1024 + 1024) * sizeof(char));
            byte* buffer = stackalloc byte[size];

            for (int i = 0; i < size; i++)
            {
                buffer[i] = 0;
            }

            var properties = (EVENT_TRACE_PROPERTIES*)buffer;
            properties->Wnode.BufferSize = (uint)size;
            properties->LoggerNameOffset = (uint)sizeof(EVENT_TRACE_PROPERTIES);
            properties->LogFileNameOffset = (uint)(sizeof(EVENT_TRACE_PROPERTIES) + (1024 * sizeof(char)));

            int status = NativeMethods.ControlTrace(0, name, properties, NativeConstants.EVENT_TRACE_CONTROL_QUERY);
            Assert.Equal(NativeConstants.ERROR_SUCCESS, status);

            return properties->LogFileMode;
        }

        [Fact]
        public void UserTraceDefaultsToOneBufferPoolForTheWholeSession()
        {
            string name = "Krabs-Managed-Tests-" + Guid.NewGuid().ToString("N");

            using (var trace = new UserTrace(name))
            {
                trace.Open();

                uint mode = QueryLogFileMode(name);

                Assert.Equal(
                    NativeConstants.EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING,
                    mode & NativeConstants.EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING);
                Assert.Equal(
                    NativeConstants.EVENT_TRACE_REAL_TIME_MODE,
                    mode & NativeConstants.EVENT_TRACE_REAL_TIME_MODE);

                trace.Stop();
            }
        }

        [Fact]
        public void UserTraceHonoursAnExplicitLogFileModeWithoutAddingNoPerProcessorBuffering()
        {
            string name = "Krabs-Managed-Tests-" + Guid.NewGuid().ToString("N");

            using (var trace = new UserTrace(name))
            {
                // Matches native krabs' describe_UserTrace.it_should_set_properties: a caller
                // that names a mode explicitly is trusted to have chosen it deliberately, so
                // NO_PER_PROCESSOR_BUFFERING must not be added behind its back.
                trace.SetTraceProperties(new EventTraceProperties
                {
                    BufferSize = 1024,
                    LogFileMode = NativeConstants.EVENT_TRACE_REAL_TIME_MODE,
                });
                trace.Open();

                uint mode = QueryLogFileMode(name);

                Assert.Equal(
                    NativeConstants.EVENT_TRACE_REAL_TIME_MODE,
                    mode & NativeConstants.EVENT_TRACE_REAL_TIME_MODE);
                Assert.Equal(0u, mode & NativeConstants.EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING);

                trace.Stop();
            }
        }

        [Fact]
        public void KernelTraceDefaultsToOneBufferPoolForTheWholeSession()
        {
            string name = "Krabs-Managed-Tests-" + Guid.NewGuid().ToString("N");

            using (var trace = new KernelTrace(name))
            {
                trace.Enable(new ProcessProvider());
                trace.Open();

                uint mode = QueryLogFileMode(name);

                Assert.Equal(
                    NativeConstants.EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING,
                    mode & NativeConstants.EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING);
                Assert.Equal(
                    NativeConstants.EVENT_TRACE_SYSTEM_LOGGER_MODE,
                    mode & NativeConstants.EVENT_TRACE_SYSTEM_LOGGER_MODE);

                trace.Stop();
            }
        }

        [Fact]
        public void KernelTraceAlwaysAddsSystemLoggerModeEvenWithAnExplicitLogFileMode()
        {
            string name = "Krabs-Managed-Tests-" + Guid.NewGuid().ToString("N");

            using (var trace = new KernelTrace(name))
            {
                trace.Enable(new ProcessProvider());
                trace.SetTraceProperties(new EventTraceProperties
                {
                    BufferSize = 1024,
                    LogFileMode = NativeConstants.EVENT_TRACE_REAL_TIME_MODE,
                });
                trace.Open();

                uint mode = QueryLogFileMode(name);

                Assert.Equal(
                    NativeConstants.EVENT_TRACE_SYSTEM_LOGGER_MODE,
                    mode & NativeConstants.EVENT_TRACE_SYSTEM_LOGGER_MODE);
                Assert.Equal(0u, mode & NativeConstants.EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING);

                trace.Stop();
            }
        }
    }
}
