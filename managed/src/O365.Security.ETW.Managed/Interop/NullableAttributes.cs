#if !NET

using System;

namespace System.Diagnostics.CodeAnalysis
{
    /// <summary>
    /// Declares that an out parameter may be null when the method returns the given value.
    /// </summary>
    /// <remarks>
    /// The .NET Framework reference assemblies predate nullable reference types and do not
    /// carry these attributes, so they are declared here for net462 and net48. The compiler
    /// matches them by full name rather than by identity, so a consumer gets the same flow
    /// analysis it would from the in-box attribute even though this one is internal.
    ///
    /// Without this, every <c>TryGet*</c> would have to be annotated <c>out string?</c>, which
    /// forces a null check on callers even in the branch where the call returned true.
    /// </remarks>
    [AttributeUsage(AttributeTargets.Parameter, Inherited = false)]
    internal sealed class MaybeNullWhenAttribute : Attribute
    {
        public MaybeNullWhenAttribute(bool returnValue)
        {
            ReturnValue = returnValue;
        }

        /// <summary>The return value for which the parameter may be null.</summary>
        public bool ReturnValue { get; }
    }

    /// <summary>
    /// Declares that an out parameter is not null when the method returns the given value.
    /// </summary>
    [AttributeUsage(AttributeTargets.Parameter, Inherited = false)]
    internal sealed class NotNullWhenAttribute : Attribute
    {
        public NotNullWhenAttribute(bool returnValue)
        {
            ReturnValue = returnValue;
        }

        /// <summary>The return value for which the parameter is not null.</summary>
        public bool ReturnValue { get; }
    }
}

#endif
