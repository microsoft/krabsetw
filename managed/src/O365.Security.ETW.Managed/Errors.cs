using System;

namespace Microsoft.O365.Security.ETW
{
    /// <summary>Thrown when the ETW trace object is already registered.</summary>
    public class TraceAlreadyRegistered : Exception
    {
        public TraceAlreadyRegistered() { }

        public TraceAlreadyRegistered(string message) : base(message) { }
    }

    /// <summary>Thrown when an invalid parameter is provided.</summary>
    public class InvalidParameter : Exception
    {
        public InvalidParameter() { }

        public InvalidParameter(string message) : base(message) { }
    }

    /// <summary>Thrown when the trace fails to open.</summary>
    public class OpenTraceFailure : Exception
    {
        public OpenTraceFailure() { }

        public OpenTraceFailure(string message) : base(message) { }
    }

    /// <summary>Thrown when the schema for an event could not be found.</summary>
    public class CouldNotFindSchema : Exception
    {
        public CouldNotFindSchema() { }

        public CouldNotFindSchema(string message) : base(message) { }
    }

    /// <summary>Thrown when an error occurs that we did not explicitly handle.</summary>
    public class UnexpectedError : Exception
    {
        public UnexpectedError() { }

        public UnexpectedError(string message) : base(message) { }
    }

    /// <summary>Thrown when an error is encountered parsing an ETW property.</summary>
    public class ParserException : Exception
    {
        public ParserException() { }

        public ParserException(string message) : base(message) { }
    }

    /// <summary>
    /// Thrown when a requested type does not match the ETW property type.
    /// </summary>
    /// <remarks>
    /// The C++/CLI wrapper only raises this in debug builds, because the check lives behind
    /// an assert in native krabs. The port raises it in every build: the check is a couple of
    /// integer comparisons against schema data that has already been resolved, and silently
    /// reinterpreting a property is worse than the cost of the comparison.
    /// </remarks>
    public class TypeMismatchAssert : Exception
    {
        public TypeMismatchAssert() { }

        public TypeMismatchAssert(string message) : base(message) { }
    }

    /// <summary>Thrown on internal parsing errors when retrieving container IDs.</summary>
    public class ContainerIdFormatException : Exception
    {
        public ContainerIdFormatException() { }

        public ContainerIdFormatException(string message) : base(message) { }
    }

    /// <summary>
    /// Thrown when no trace sessions remain to register. An existing trace session must be
    /// deleted first.
    /// </summary>
    public class NoTraceSessionsRemaining : Exception
    {
        public NoTraceSessionsRemaining() { }

        public NoTraceSessionsRemaining(string message) : base(message) { }
    }
}
