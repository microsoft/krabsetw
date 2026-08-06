using System;

namespace Microsoft.O365.Security.ETW
{
    /// <summary>Receives an event on the zero-copy path.</summary>
    public delegate void EventRecordDelegate(in EventRecordRef record);

    /// <summary>Receives an event through the compatibility interface.</summary>
    public delegate void IEventRecordDelegate(IEventRecord record);

    /// <summary>Receives event metadata through the compatibility interface.</summary>
    public delegate void IEventRecordMetadataDelegate(IEventRecordMetadata record);

    /// <summary>Receives a failure raised while dispatching an event.</summary>
    public delegate void EventRecordErrorDelegate(IEventRecordError error);

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
}
