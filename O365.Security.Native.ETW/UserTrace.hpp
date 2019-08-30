// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma once

#include <msclr\marshal.h>
#include <msclr\marshal_cppstd.h>

#include <krabs.hpp>

#include "ITrace.hpp"
#include "NativePtr.hpp"
#include "Provider.hpp"
#include "RawProvider.hpp"
#include "Errors.hpp"
#include "TraceStats.hpp"

using namespace System;
using namespace System::Runtime::InteropServices;

namespace Microsoft { namespace O365 { namespace Security { namespace ETW {

    /// <summary>
    /// Represents an owned user trace.
    /// </summary>
    public ref class UserTrace : public IUserTrace, public IDisposable {
    public:

        /// <summary>
        /// Constructs a user trace session with a generated name.
        /// </summary>
        /// <example>
        ///     var UserTrace trace = new UserTrace();
        /// </example>
        UserTrace();

        /// <summary>
        /// Stops the user trace when disposed.
        /// </summary>
        ~UserTrace();

        /// <summary>
        /// Constructs a named user trace session, where the name can be
        /// any arbitrary, unique string.
        /// </summary>
        /// <param name="name">the name to assign to the UserTrace object</param>
        /// <example>
        ///     var trace = new UserTrace("Purdy kitty");
        /// </example>
        UserTrace(String^ name);

        /// <summary>
        /// Enables a provider for the given user trace.
        /// </summary>
        /// <param name="provider">the <see cref="O365::Security::ETW::Provider"/> to enable on the trace</param>
        /// <example>
        ///     UserTrace trace = new UserTrace();
        ///     System.Guid powershell = System.Guid.Parse("{...}")
        ///     Provider provider = new Provider(powershell);
        ///     trace.Enable(provider);
        /// </example>
        virtual void Enable(O365::Security::ETW::Provider ^provider);

        /// <summary>
        /// Enables a raw provider for the given user trace.
        /// </summary>
        /// <param name="provider">the <see cref="O365::Security::ETW::RawProvider"/> to enable on the trace</param>
        /// <example>
        ///     UserTrace trace = new UserTrace();
        ///     System.Guid powershell = System.Guid.Parse("{...}")
        ///     Provider provider = new RawProvider(powershell);
        ///     trace.Enable(provider);
        /// </example>
        virtual void Enable(O365::Security::ETW::RawProvider ^provider);

        /// <summary>
        /// Starts listening for events from the enabled providers.
        /// </summary>
        /// <example>
        ///     UserTrace trace = new UserTrace();
        ///     // ...
        ///     trace.Start();
        /// </example>
        /// <remarks>
        /// This function is a blocking call. Whichever thread calls Start() is effectively
        /// donating itself to the ETW subsystem as the processing thread for events.
        ///
        /// A side effect of this is that it is expected that Stop() will be called on
        /// a different thread.
        /// </remarks>
        virtual void Start();

        /// <summary>
        /// Stops listening for events.
        /// </summary>
        /// <example>
        ///     UserTrace trace = new UserTrace();
        ///     // ...
        ///     trace.Start();
        ///     trace.Stop();
        /// </example>
        virtual void Stop();

        /// <summary>
        /// Get stats about events handled by this trace
        /// </summary>
        /// <returns>the <see cref="O365::Security::ETW::TraceStats"/> for the current trace object</returns>
        virtual TraceStats QueryStats();

    internal:
        bool disposed_ = false;
        O365::Security::ETW::NativePtr<krabs::user_trace> trace_;
    };

    // Implementation
    // ------------------------------------------------------------------------

    inline UserTrace::UserTrace()
        : trace_(new krabs::user_trace())
    {
    }

    inline UserTrace::~UserTrace()
    {
        if (disposed_)
        {
            return;
        }

        try
        {
            Stop();
        }
        catch (...)
        {
            // Stop may throw if the trace has been removed by another process.
            // We catch and swallow the exception here to avoid an exception from leaking
            // out of the destructor, which may cause a crash.
        }

        disposed_ = true;
    }

    inline UserTrace::UserTrace(String ^name)
        : trace_()
    {
        std::wstring nativeName = msclr::interop::marshal_as<std::wstring>(name);
        trace_.Swap(O365::Security::ETW::NativePtr<krabs::user_trace>(nativeName));
    }

    inline void UserTrace::Enable(O365::Security::ETW::Provider ^provider)
    {
        return trace_->enable(*provider->provider_);
    }

    inline void UserTrace::Enable(O365::Security::ETW::RawProvider ^provider)
    {
        return trace_->enable(*provider->provider_);
    }

    inline void UserTrace::Start()
    {
        ExecuteAndConvertExceptions(return trace_->start());
    }

    inline void UserTrace::Stop()
    {
        ExecuteAndConvertExceptions(return trace_->stop());
    }

    inline TraceStats UserTrace::QueryStats()
    {
        ExecuteAndConvertExceptions(return TraceStats(trace_->query_stats()));
    }

} } } }