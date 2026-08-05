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
    public delegate void EventRecordErrorDelegate(EventRecordError error);

    /// <summary>
    /// Reports a failure that occurred while handling an event.
    /// </summary>
    public sealed class EventRecordError
    {
        internal EventRecordError(string message, IEventRecordMetadata record)
        {
            Message = message;
            Record = record;
        }

        public string Message { get; }

        public IEventRecordMetadata Record { get; }
    }
}
