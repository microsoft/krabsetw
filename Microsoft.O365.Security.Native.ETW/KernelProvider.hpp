// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma once

#include <krabs.hpp>
#include <krabs/perfinfo_groupmask.hpp>

#include "Callbacks.hpp"
#include "Guid.hpp"
#include "NativePtr.hpp"
#include "Filtering/EventFilter.hpp"

using namespace System;
using namespace System::Runtime::InteropServices;

namespace Microsoft { namespace O365 { namespace Security { namespace ETW {

    /// <summary>
    /// Represents a kernel trace provider and its configuration.
    /// </summary>
    public ref class KernelProvider {
    public:

        /// <summary>
        /// Constructs a KernelProvider that is identified by its GUID.
        /// </summary>
        /// <param name="flags">the trace flags to set</param>
        /// <param name="id">the guid of the kernel trace</param>
        /// <remarks>
        /// More information about trace flags can be found on MSDN:
        /// <see href="https://msdn.microsoft.com/en-us/library/windows/desktop/aa363784(v=vs.85).aspx"/>
        /// </remarks>
        KernelProvider(unsigned int flags, System::Guid id);

        /// <summary>
        /// Constructs a KernelProvider that is identified by its GUID.
        /// </summary>
        /// <param name="id">the guid of the kernel trace</param>
        /// <param name="mask">the group mask to set</param>
        /// <remarks>
        /// Only supported on Windows 8 and newer.
        /// More information about group masks can be found here:
        /// <see href="https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/etw/tracesup/perfinfo_groupmask.htm"/>
        /// </remarks>
        KernelProvider(System::Guid id, PERFINFO_MASK mask);

        /// <summary>
        /// Adds a new EventFilter to the provider.
        /// </summary>
        /// <param name="filter">
        /// the <see cref="O365::Security::ETW::EventFilter"/> to
        /// filter incoming events with
        /// </param>
        void AddFilter(O365::Security::ETW::EventFilter ^filter) {
            provider_->add_filter(filter);
        }

        /// <summary>
        /// An event that is invoked when an ETW event is fired in this
        /// provider.
        /// </summary>
        event IEventRecordMetadataDelegate^ OnMetadata {
            void add(IEventRecordMetadataDelegate^ value) { CombineDelegate(bridge_->OnMetadata, value); }
            void remove(IEventRecordMetadataDelegate^ value) { RemoveDelegate(bridge_->OnMetadata, value); }
        }

        /// <summary>
        /// An event that is invoked when an ETW event is fired in this
        /// provider.
        /// </summary>
        event IEventRecordDelegate^ OnEvent {
            void add(IEventRecordDelegate^ value) { CombineDelegate(bridge_->OnEvent, value); }
            void remove(IEventRecordDelegate^ value) { RemoveDelegate(bridge_->OnEvent, value); }
        }

        /// <summary>
        /// An event that is invoked when an ETW event is received
        /// but an error occurs handling the record.
        /// </summary>
        event EventRecordErrorDelegate^ OnError {
            void add(EventRecordErrorDelegate^ value) { CombineDelegate(bridge_->OnError, value); }
            void remove(EventRecordErrorDelegate^ value) { RemoveDelegate(bridge_->OnError, value); }
        }

        /// <summary>
        /// Retrieves the GUID associated with this provider
        /// </summary>
        /// <returns>returns the GUID associated with this provider object</returns>
        property Guid Id {
            Guid get() {
                GUID guid = provider_->id();
                return Guid(guid.Data1, guid.Data2, guid.Data3,
                            guid.Data4[0], guid.Data4[1],
                            guid.Data4[2], guid.Data4[3],
                            guid.Data4[4], guid.Data4[5],
                            guid.Data4[6], guid.Data4[7]);
            }
        }

    internal:
        NativePtr<krabs::kernel_provider> provider_;
        CallbackBridge^ bridge_ = gcnew CallbackBridge();

        void RegisterCallbacks();
    };

    // Implementation
    // ------------------------------------------------------------------------

    inline KernelProvider::KernelProvider(unsigned int flags, System::Guid id)
    : provider_(flags, ConvertGuid(id))
    {
        RegisterCallbacks();
    }

    inline KernelProvider::KernelProvider(System::Guid id, PERFINFO_MASK mask)
        : provider_(ConvertGuid(id), mask)
    {
        RegisterCallbacks();
    }

    inline void KernelProvider::RegisterCallbacks()
    {
        provider_->add_on_event_callback(bridge_->GetOnEventBridge());
        provider_->add_on_error_callback(bridge_->GetOnErrorBridge());
    }

} } } }