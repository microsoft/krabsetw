using System;
using System.Runtime.InteropServices;
using System.Threading;
using Microsoft.Win32.SafeHandles;

namespace Microsoft.O365.Security.ETW.Interop
{
    /// <summary>
    /// An unmanaged allocation from <see cref="Marshal.AllocHGlobal(int)"/>.
    /// </summary>
    /// <remarks>
    /// Wrapping these rather than holding a raw <see cref="IntPtr"/> is what the platform
    /// recommends, and it buys three things here.
    ///
    /// Release is *critical* finalization: a <see cref="SafeHandle"/> derives from
    /// CriticalFinalizerObject, so its release runs after every ordinary finalizer. That
    /// ordering matters for the trace logger name — ETW reads it for as long as the trace
    /// handle is open, and a trace's own finalizer is what closes that handle. An ordinary
    /// finalizer on the allocation could run first and free memory ETW was still reading.
    ///
    /// It also removes the hand-written finalizers from the types that merely *hold*
    /// allocations, so each allocation cleans itself up exactly once, and it stops the handle
    /// being collected underneath a P/Invoke that was passed it.
    ///
    /// The hot path is unaffected: callers that read the memory per event cache the raw
    /// pointer once, and this object keeps it alive.
    /// </remarks>
    internal sealed class SafeHGlobalHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        /// <summary>
        /// Allocations made and not yet released, across the process.
        /// </summary>
        /// <remarks>
        /// Kept so a test can prove that abandoning an owner really does release its memory.
        /// Allocation happens per schema and per trace, never per event.
        /// </remarks>
        internal static int LiveAllocations;

        /// <summary>Allocates <paramref name="bytes"/> of unmanaged memory.</summary>
        public SafeHGlobalHandle(int bytes)
            : base(true)
        {
            SetHandle(Marshal.AllocHGlobal(bytes));
            Interlocked.Increment(ref LiveAllocations);
        }

        private SafeHGlobalHandle(IntPtr allocated)
            : base(true)
        {
            SetHandle(allocated);
            Interlocked.Increment(ref LiveAllocations);
        }

        /// <summary>Copies a string into unmanaged memory as NUL-terminated UTF-16.</summary>
        public static SafeHGlobalHandle FromUnicodeString(string value)
        {
            return new SafeHGlobalHandle(Marshal.StringToHGlobalUni(value));
        }

        /// <summary>
        /// The raw pointer, for a caller that needs it per event. Only valid while this object
        /// is reachable, which is the caller's responsibility to arrange.
        /// </summary>
        public IntPtr Pointer
        {
            get { return handle; }
        }

        protected override bool ReleaseHandle()
        {
            Marshal.FreeHGlobal(handle);
            Interlocked.Decrement(ref LiveAllocations);
            return true;
        }
    }
}
