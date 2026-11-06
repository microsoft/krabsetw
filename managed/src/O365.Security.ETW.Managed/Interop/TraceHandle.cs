using System;
using System.Runtime.ConstrainedExecution;
using System.Threading;

namespace Microsoft.O365.Security.ETW.Interop
{
    /// <summary>
    /// A consumer handle returned by <c>OpenTrace</c>, closed with <c>CloseTrace</c>.
    /// </summary>
    /// <remarks>
    /// Deliberately not a <see cref="System.Runtime.InteropServices.SafeHandle"/>, for two
    /// reasons.
    ///
    /// A SafeHandle stores an <see cref="IntPtr"/>, and <c>TRACEHANDLE</c> is a
    /// <c>ULONG64</c> on every architecture. Squeezing one into a 32-bit IntPtr is lossy
    /// above 32 bits — measured: <c>0x0000000100000000</c> converts back as <c>0</c>. The
    /// documented failure value is <c>(UINT64)UINTPTR_MAX</c>, which implies real handles are
    /// pointer-shaped, but that is an inference from the sentinel rather than a documented
    /// guarantee, and the sentinel itself differs between pre-Vista and Vista+. Holding the
    /// <c>ULONG64</c> as-is needs no such assumption.
    ///
    /// SafeHandle's reference counting is also backwards here. ETW requires <c>CloseTrace</c>
    /// to be callable *while* <c>ProcessTrace</c> is running — that is how processing is
    /// stopped — whereas a ref count taken around the call would defer the close until the
    /// call returned, which is exactly what must not happen.
    ///
    /// What is worth keeping from SafeHandle is critical finalization, which this inherits
    /// from <see cref="CriticalFinalizerObject"/>: the finalizer is prepared ahead of time
    /// and runs after ordinary finalizers, so a trace's own finalizer still gets to run first.
    /// </remarks>
    internal sealed class TraceHandle : CriticalFinalizerObject, IDisposable
    {
        /// <summary>
        /// The <c>TRACEHANDLE</c>, held as a long so <see cref="Interlocked"/> can swap it.
        /// long and ulong are the same 64 bits, so nothing is lost either way.
        /// </summary>
        private long _handle;

        public TraceHandle(ulong handle)
        {
            _handle = unchecked((long)handle);
        }

        /// <summary>The handle as ETW's <c>TRACEHANDLE</c>.</summary>
        public ulong Value
        {
            get { return unchecked((ulong)Volatile.Read(ref _handle)); }
        }

        /// <summary>
        /// Whether <c>OpenTrace</c> failed. The sentinel is pointer-width on Vista and later,
        /// so it differs between a 32- and 64-bit process.
        /// </summary>
        public bool IsInvalid
        {
            get
            {
                ulong value = Value;
                return value == 0 || value == Invalid;
            }
        }

        private static ulong Invalid
        {
            get { return IntPtr.Size == 8 ? ulong.MaxValue : 0x00000000FFFFFFFFUL; }
        }

        public void Dispose()
        {
            Close();
            GC.SuppressFinalize(this);
        }

        ~TraceHandle()
        {
            Close();
        }

        private void Close()
        {
            ulong value = unchecked((ulong)Interlocked.Exchange(ref _handle, 0));

            if (value != 0 && value != Invalid)
            {
                // The return is deliberately ignored: ERROR_CTX_CLOSE_PENDING is the ordinary
                // answer when ProcessTrace is still draining, and there is nothing a caller
                // -- least of all a finalizer -- could do about any other failure.
                NativeMethods.CloseTrace(value);
            }
        }
    }
}
