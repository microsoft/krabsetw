using System;

namespace Microsoft.O365.Security.ETW
{
    /// <summary>
    /// Receives an event as a view into the payload, allocating nothing.
    /// </summary>
    /// <remarks>
    /// A handler must declare its parameter explicitly
    /// (<c>(in EventRecordRef record) =&gt; ...</c>). An implicitly typed lambda cannot be
    /// converted to this delegate, because a lambda cannot infer the <c>in</c> modifier.
    /// </remarks>
    public delegate void EventRecordDelegate(in EventRecordRef record);

    /// <summary>Receives an event through the compatibility interface.</summary>
    public delegate void IEventRecordDelegate(IEventRecord record);

    /// <summary>Receives event metadata through the compatibility interface.</summary>
    public delegate void IEventRecordMetadataDelegate(IEventRecordMetadata record);

    /// <summary>Receives a failure raised while dispatching an event.</summary>
    public delegate void EventRecordErrorDelegate(IEventRecordError error);

    /// <summary>Receives an exception thrown out of a consumer's event handler.</summary>
    public delegate void EventRecordExceptionDelegate(IEventRecordException exception);

    /// <summary>
    /// Reports a failure that occurred while handling an event.
    /// </summary>
    public interface IEventRecordError
    {
        /// <summary>Describes the failure.</summary>
        string Message { get; }

        /// <summary>The event that could not be handled.</summary>
        IEventRecordMetadata Record { get; }
    }

    /// <summary>
    /// Reports a failure that occurred while handling an event.
    /// </summary>
    public sealed class EventRecordError : IEventRecordError
    {
        internal EventRecordError(string message, IEventRecordMetadata record)
        {
            Message = message;
            Record = record;
        }

        /// <inheritdoc/>
        public string Message { get; }

        /// <inheritdoc/>
        public IEventRecordMetadata Record { get; }
    }

    /// <summary>
    /// Reports an exception that escaped a consumer's event handler.
    /// </summary>
    /// <remarks>
    /// Distinct from <see cref="IEventRecordError"/>, which reports the library failing to
    /// decode an event. This reports the consumer's own code failing to handle one.
    /// </remarks>
    public interface IEventRecordException
    {
        /// <summary>The exception the handler threw.</summary>
        Exception Exception { get; }

        /// <summary>
        /// The event being handled when it threw.
        /// </summary>
        /// <remarks>
        /// Valid only for the duration of the callback, like every other record surface: it
        /// views a buffer ETW takes back on return. Copy what you need out of it.
        /// </remarks>
        IEventRecordMetadata Record { get; }

        /// <summary>
        /// Whether the trace is stopping because of this exception, which is the default.
        /// See <see cref="UserTrace.StopOnHandlerException"/>.
        /// </summary>
        bool Stopping { get; }
    }

    /// <summary>
    /// Reports an exception that escaped a consumer's event handler.
    /// </summary>
    public sealed class EventRecordException : IEventRecordException
    {
        internal EventRecordException(Exception exception, IEventRecordMetadata record, bool stopping)
        {
            Exception = exception;
            Record = record;
            Stopping = stopping;
        }

        /// <inheritdoc/>
        public Exception Exception { get; }

        /// <inheritdoc/>
        public IEventRecordMetadata Record { get; }

        /// <inheritdoc/>
        public bool Stopping { get; }
    }
}
