// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma once

namespace O365 { namespace Security { namespace ETW {

    /// <summary>
    /// Thrown when the ETW trace object is already registered.
    /// </summary>
    public ref struct TraceAlreadyRegistered : public System::Exception {};

    /// <summary>
    /// Thrown when an invalid parameter is provided.
    /// </summary>
    public ref struct InvalidParameter : public System::Exception {};

    /// <summary>
    /// Thrown when the trace fails to start.
    /// </summary>
    public ref struct StartTraceFailure : public System::Exception {};

    /// <summary>
    /// Thrown when the schema for an event could not be found.
    /// </summary>
    public ref struct CouldNotFindSchema : public System::Exception {};

    /// <summary>
    /// Thrown when an error is encountered parsing an ETW property.
    /// </summary>
    public ref struct ParserException : public System::Exception {
        /// <param name="msg">the error message returned while parsing</param>
        ParserException(System::String^ msg) : System::Exception(msg) { }
    };

    /// <summary>
    /// Thrown when a requested type does not match the ETW property type.
    /// NOTE: This is only thrown in debug builds.
    /// </summary>
    public ref struct TypeMismatchAssert : public System::Exception {
        /// <param name="msg">the error message returned when types mismatched</param>
        TypeMismatchAssert(System::String^ msg) : System::Exception(msg) { }
    };

    /// <summary>
    /// Thrown when no trace sessions remaining to register. An existing trace
    /// session must be deleted first.
    /// </summary>
    public ref struct NoTraceSessionsRemaining : public System::Exception {};

#define ExecuteAndConvertExceptions(e) \
        try { e; } \
        catch (const krabs::trace_already_registered &) \
        { \
            throw gcnew TraceAlreadyRegistered; \
        } \
        catch (const krabs::invalid_parameter &) \
        { \
            throw gcnew InvalidParameter; \
        } \
        catch (const krabs::start_trace_failure &) \
        { \
            throw gcnew StartTraceFailure; \
        } \
        catch (const krabs::no_trace_sessions_remaining &) \
        { \
            throw gcnew NoTraceSessionsRemaining; \
        } \

} } }