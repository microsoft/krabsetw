using Microsoft.O365.Security.ETW;

namespace Microsoft.O365.Security.ETW.Tests
{
    /// <summary>
    /// Stands in for the trace a <see cref="TraceContext"/> would stop, and records that it
    /// was asked to.
    /// </summary>
    /// <remarks>
    /// Lets a test observe the stop request without a live ETW session, which is otherwise the
    /// only way that call becomes visible.
    /// </remarks>
    internal sealed class StubTraceHost : ITraceHost
    {
        /// <summary>How many times the context asked for the trace to stop.</summary>
        public int Stops { get; private set; }

        public void Stop()
        {
            Stops++;
        }
    }
}
