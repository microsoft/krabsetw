using System;
using System.Reflection;
using Microsoft.O365.Security.ETW.Interop;
using Xunit;

namespace Microsoft.O365.Security.ETW.Tests
{
    /// <summary>
    /// Covers teardown when <see cref="UserTrace.Open"/> did not complete.
    /// </summary>
    /// <remarks>
    /// An ETW session is a machine-wide object that outlives the process that created it, so
    /// leaking one is worse than leaking memory. `Open` creates the session first and can then
    /// throw before it finishes — `EnableTraceEx2` and `OpenTrace` both can — which leaves a
    /// live session behind while the trace never reached its opened state.
    ///
    /// Teardown therefore has to key off what actually exists rather than off that flag,
    /// because the ordinary path is `using`, and a `Dispose` that decides there is nothing to
    /// do also suppresses the finalizer that would otherwise have cleaned up.
    /// </remarks>
    [Collection("etw")]
    public unsafe class FailedOpenTeardownTests
    {
        private const int ErrorWmiInstanceNotFound = 4201;

        /// <summary>
        /// Asks ETW to stop a session by name. Returns the status, so the caller can tell an
        /// orphan (it was there, and is now stopped) from a clean teardown.
        /// </summary>
        private static int StopByName(string name)
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

            return NativeMethods.ControlTrace(0, name, properties, NativeConstants.EVENT_TRACE_CONTROL_STOP);
        }

        [Fact]
        public void DisposeStopsTheSessionWhenOpenDidNotComplete()
        {
            string name = "Krabs-FailedOpen-" + Guid.NewGuid().ToString("N");

            var trace = new UserTrace(name);
            trace.Enable(new Provider(TestTraceLoggingSource.ProviderGuid) { Any = 0 });
            trace.Open();

            // Reproduces the state Open leaves behind when it throws after StartTrace has
            // already created the session: the session exists, but the trace never finished
            // opening. Forcing the flag is the only deterministic way to reach it, since the
            // real triggers are native calls failing.
            FieldInfo opened = typeof(UserTrace).GetField("_opened", BindingFlags.NonPublic | BindingFlags.Instance)!;
            opened.SetValue(trace, false);

            trace.Dispose();

            int status = StopByName(name);

            Assert.Equal(ErrorWmiInstanceNotFound, status);
        }

        /// <summary>
        /// The ordinary path must keep working: a trace that opened and stopped normally
        /// leaves no session behind either.
        /// </summary>
        [Fact]
        public void DisposeStopsTheSessionOnTheNormalPath()
        {
            string name = "Krabs-FailedOpen-" + Guid.NewGuid().ToString("N");

            using (var trace = new UserTrace(name))
            {
                trace.Enable(new Provider(TestTraceLoggingSource.ProviderGuid) { Any = 0 });
                trace.Open();
                trace.Stop();
            }

            Assert.Equal(ErrorWmiInstanceNotFound, StopByName(name));
        }
    }
}
