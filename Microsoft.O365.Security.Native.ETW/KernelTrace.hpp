// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma once

#include <msclr\marshal.h>
#include <msclr\marshal_cppstd.h>

#include <krabs.hpp>

#include "ITrace.hpp"
#include "NativePtr.hpp"
#include "Provider.hpp"
#include "KernelProvider.hpp"
#include "Errors.hpp"
#include "TraceStats.hpp"

using namespace System;
using namespace System::Runtime::InteropServices;

namespace Microsoft { namespace O365 { namespace Security { namespace ETW {

    /// <summary>
    /// Represents an owned user trace.
    /// </summary>
    public ref class KernelTrace : public IKernelTrace, public IDisposable {
    public:

        /// <summary>
        /// Constructs a kernel trace session with a generated name (or the
        /// required kernel trace name on pre-Win8 machines)
        /// </summary>
        /// <example>
        ///     KernelTrace trace = new KernelTrace();
        /// </example>
        KernelTrace();

        /// <summary>
        /// Stops the trace when disposed.
        /// </summary>
        ~KernelTrace();

        /// <summary>
        /// Constructs a named kernel trace session, where the name can be
        /// any arbitrary, unique string. On pre-Win8 machines, the trace name
        /// will be the required kernel trace name and not the given one.
        /// </summary>
        /// <param name="name">the name to use for the trace</param>
        /// <example>
        ///     KernelTrace trace = new KernelTrace("Purdy kitty");
        /// </example>
        KernelTrace(String^ name);

        /// <summary>
        /// Enables a provider for the given trace.
        /// </summary>
        /// <param name="provider">
        /// the <see cref="O365::Security::ETW::KernelProvider"/> to
        /// register with the current trace object
        /// </param>
        /// <example>
        ///     KernelTrace trace = new KernelTrace();
        ///     KernelProvider provider = new Kernel.NetworkTcpipProvider()
        ///     trace.Enable(provider);
        /// </example>
        virtual void Enable(O365::Security::ETW::KernelProvider ^provider);

        virtual void Set(EventTraceProperties^ properties);

        /// <summary>
        /// Starts listening for events from the enabled providers.
        /// </summary>
        /// <example>
        ///     KernelTrace trace = new KernelTrace();
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
        ///     KernelTrace trace = new KernelTrace();
        ///     // ...
        ///     trace.Start();
        ///     trace.Stop();
        /// </example>
        virtual void Stop();

        /// <summary>
        /// Get stats about events handled by this trace
        /// </summary>
        /// <returns>a <see cref="O365::Security::ETW::TraceStats"/> object representing the stats of the current trace</returns>
        virtual TraceStats QueryStats();

    internal:
        bool disposed_ = false;
        O365::Security::ETW::NativePtr<krabs::kernel_trace> trace_;
    };

    // Implementation
    // ------------------------------------------------------------------------

    inline KernelTrace::KernelTrace()
        : trace_(new krabs::kernel_trace())
    { }

    inline KernelTrace::~KernelTrace()
    {
        if (disposed_) {
            return;
        }

        Stop();
        disposed_ = true;
    }

    inline KernelTrace::KernelTrace(String ^name)
        : trace_()
    {
        std::wstring nativeName = msclr::interop::marshal_as<std::wstring>(name);
        trace_.Swap(O365::Security::ETW::NativePtr<krabs::kernel_trace>(nativeName));
    }

    inline void KernelTrace::Enable(O365::Security::ETW::KernelProvider ^provider)
    {
        return trace_->enable(*provider->provider_);
    }

    inline void KernelTrace::Set(EventTraceProperties^ properties)
    {
        EVENT_TRACE_PROPERTIES _properties;
        _properties.BufferSize = properties->BufferSize;
        _properties.MinimumBuffers = properties->MinimumBuffers;
        _properties.MaximumBuffers = properties->MaximumBuffers;
        _properties.LogFileMode = properties->LogFileMode;
        _properties.FlushTimer = properties->FlushTimer;
        ExecuteAndConvertExceptions(return trace_->set(&_properties));
    }

    inline void KernelTrace::Start()
    {
        try
        {
            return trace_->start();
        }
        catch (const krabs::trace_already_registered &)
        {
            throw gcnew TraceAlreadyRegistered;
        }
        catch (const krabs::invalid_parameter &)
        {
            throw gcnew InvalidParameter;
        }
        catch (const krabs::open_trace_failure &)
        {
            throw gcnew OpenTraceFailure;
        }
        catch (const krabs::no_trace_sessions_remaining &)
        {
            throw gcnew NoTraceSessionsRemaining;
        }
        catch (const krabs::need_to_be_admin_failure &)
        {
            throw gcnew UnauthorizedAccessException("Need to be admin");
        }
    }

    inline void KernelTrace::Stop()
    {
        return trace_->stop();
    }

    inline TraceStats KernelTrace::QueryStats()
    {
        return TraceStats(trace_->query_stats());
    }

} } } }