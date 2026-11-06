using Xunit;

// This suite is not safe to run in parallel, and the reason is not incidental: several tests
// assert on counters that are global to the process -- TraceRegistry.InUse, which counts
// registered trace contexts, and SafeHGlobalHandle.LiveAllocations, which counts live unmanaged
// blocks. Such an assertion is only meaningful when nothing else is running, because any other
// test that opens a trace or allocates a schema blob moves the same counter. A trace is a
// machine-global resource besides: the kernel logger is a single instance, and sessions come
// from a fixed system-wide pool.
//
// The cost of serializing is nil. The live ETW tests dominate the wall clock and already ran one
// at a time inside the "etw" collection, so the suite takes the same ~50s either way; measured,
// not assumed. That makes this strictly better than the alternative of working out which class
// may run beside which -- an invariant nobody can see when adding a test, and which broke in
// exactly that way: KernelGroupMaskTests and RundownTests opened traces from outside the "etw"
// collection for as long as they had existed, and surfaced only as an intermittent failure
// elsewhere, in StopAndDisposeTests and FinalizerTests, once the runner scheduled them together.
[assembly: CollectionBehavior(DisableTestParallelization = true)]

namespace Microsoft.O365.Security.ETW.Tests
{
    /// <summary>
    /// The collection every test that opens a real ETW session belongs to.
    /// </summary>
    /// <remarks>
    /// Parallelism is off for the whole assembly, so this no longer decides what runs beside
    /// what. It is kept because it still records which tests need a live session, and because
    /// it is what would confine the damage if parallelism were ever turned back on.
    /// </remarks>
    [CollectionDefinition("etw")]
    public class EtwCollection
    {
    }
}
