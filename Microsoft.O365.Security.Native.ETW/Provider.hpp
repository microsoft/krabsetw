// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma once

#include <krabs.hpp>

#include "Callbacks.hpp"
#include "Guid.hpp"
#include "NativePtr.hpp"
#include "Filtering/EventFilter.hpp"

using namespace System;
using namespace System::Runtime::InteropServices;

namespace Microsoft { namespace O365 { namespace Security { namespace ETW {

    ref class UserTrace;

    // Flags as documented here:
    //  https://msdn.microsoft.com/en-us/library/windows/desktop/dd392306(v=vs.85).aspx
    public enum class TraceFlags
    {
        // User SID for the event is included in the ExtendedData field
        IncludeUserSid = 0x00000001,

        // Terminal Session ID for the event is included in the ExtendedData field
        IncludeTerminalSessionId = 0x00000002,

        // Stack trace for the event is included in the ExtendedData field
        IncludeStackTrace = 0x00000004,

        // Filters out all events that do not have a non-zero keyword specified.
        IgnoreKeyword0 = 0x00000010,

        // Indicates that EnableTraceEx2 should enable a provider group rather
        // than an individual provider. See https://msdn.microsoft.com/en-us/library/windows/desktop/mt772485(v=vs.85).aspx
        EnableProviderGroup = 0x00000020,

        // Include the Process Start Key in the extended data.
        // The Process Start Key is a sequence number that identifies the process.
        // While the Process ID may be reused within a session, the Process Start Key
        // is guaranteed uniqueness in the current boot session.
        IncludeProcessStartKey = 0x00000080,

        // Include the Event Key in the extended data.
        // The Event Key is a unique identifier for the event instance that will be
        // constant across multiple trace sessions listening to this event.
        // It can be used to correlate simultaneous trace sessions.
        IncludeProcessEventKey = 0x00000100,

        // Filters out all events that are either marked as an InPrivate event
        // or come from a process that is marked as InPrivate.
        // InPrivate implies that the event or process contains some data that would be
        // considered private or personal. It is up to the process or event to designate
        // itself as InPrivate for this to work.
        ExcludeInPrivateEventKey = 0x00000200,

        // Receive events from processes running inside Windows containers
        EnableSilosEventKey = 0x00000400,

        // The container ID is included in the ExtendedData field of events
        // emitted from processes running inside Windows containers
        SourceContainerTrackingEventKey = 0x00000800,
    };

    /// <summary>
    /// Represents a user trace provider and its configuration.
    /// </summary>
    /// <remarks>
    /// The easiest way to identify providers that you can enable
    /// is to use the Message Analyzer tool: <see href="https://blogs.technet.microsoft.com/messageanalyzer/"/>
    /// </remarks>
    public ref class Provider {
    public:

        /// <summary>
        /// Specifies a reasonable default to catch all the events with a
        /// bitmask with all bits set.
        /// </summary>
        static const ULONGLONG AllBitsSet = (ULONGLONG)-1;

        /// <summary>
        /// Constructs a Provider that is identified by its GUID.
        /// </summary>
        /// <param name="id">the Guid of the provider to construct</param>
        /// <example>
        /// var provider = new Provider(Guid.Parse("{A0C1853B-5C40-4B15-8766-3CF1C58F985A}"));
        /// </example>
        Provider(System::Guid id);

        /// <summary>
        /// Constructs a Provider that is identified by the provider name.
        /// </summary>
        /// <param name="providerName">the name of the provider to construct</param>
        /// <example>
        /// var provider = new Provider("Microsoft-Windows-PowerShell");
        /// </example>
        Provider(String^ providerName);

        /// <summary>
        /// Represents the "any" value on the provider's options, where
        /// "any" is typically used to request notification if any of the
        /// matching event types fire.
        /// </summary>
        property ULONGLONG Any {
            void set(ULONGLONG value) {
                provider_->any(value);
            }
        }

        /// <summary>
        /// Represents the "all" value on the provider's options, where
        /// "all" is typically used to request notification if all of the
        /// keyword types are matched.
        /// </summary>
        property ULONGLONG All {
            void set(ULONGLONG value) {
                provider_->all(value);
            }
        }

        /// <summary>
        /// Represents the "level" value on the provider's options, where
        /// "level" determines events in what categories are 
        /// enabled for notification.
        /// </summary>
        property UCHAR Level {
            void set(UCHAR value) {
                provider_->level(value);
            }
        }

        /// <summary>
        /// Represents the "EnabledProperty" value on the provider's options.
        /// Values are documented here:
        /// https://docs.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-enable_trace_parameters
        /// </summary>
        property TraceFlags TraceFlags {
            ETW::TraceFlags get() {
                return static_cast<ETW::TraceFlags>(provider_->trace_flags());
            }

            void set(O365::Security::ETW::TraceFlags value) {
                provider_->trace_flags((ULONG)value);
            }
        }

        /// <summary>
        /// Requests that the provider log its state information. See:
        ///   https://docs.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-enabletraceex2
        /// </summary>
        /// <example>
        /// var provider = new Provider("Microsoft-Windows-Kernel-Process");
        /// provider.Any = 0x10;  // WINEVENT_KEYWORD_PROCESS
        /// provider.EnableRundownEvents();
        /// </example>
        void EnableRundownEvents() {
            provider_->enable_rundown_events();
        }

        /// <summary>
        /// Adds a new EventFilter to the provider.
        /// </summary>
        /// <param name="filter">the <see cref="O365::Security::ETW::EventFilter"/> to add</param>
        void AddFilter(O365::Security::ETW::EventFilter ^filter) {
            provider_->add_filter(filter);
        }

        /// <summary>
        /// An event that is invoked when an ETW event is fired in this
        /// provider.
        /// </summary>
        event IEventRecordMetadataDelegate^ OnMetadata {
            void add(IEventRecordMetadataDelegate^ value) { CombineDelegate(IEventRecordMetadataDelegate, bridge_->OnMetadata, value); }
            void remove(IEventRecordMetadataDelegate^ value) { RemoveDelegate(IEventRecordMetadataDelegate, bridge_->OnMetadata, value); }
        }

        /// <summary>
        /// An event that is invoked when an ETW event is fired in this
        /// provider.
        /// </summary>
        event IEventRecordDelegate^ OnEvent {
            void add(IEventRecordDelegate^ value) { CombineDelegate(IEventRecordDelegate, bridge_->OnEvent, value); }
            void remove(IEventRecordDelegate^ value) { RemoveDelegate(IEventRecordDelegate, bridge_->OnEvent, value); }
        }

        /// <summary>
        /// An event that is invoked when an ETW event is received
        /// but an error occurs handling the record.
        /// </summary>
        event EventRecordErrorDelegate^ OnError {
            void add(EventRecordErrorDelegate^ value) { CombineDelegate(EventRecordErrorDelegate, bridge_->OnError, value); }
            void remove(EventRecordErrorDelegate^ value) { RemoveDelegate(EventRecordErrorDelegate, bridge_->OnError, value); }
        }

    internal:
        NativePtr<krabs::provider<>> provider_;
        CallbackBridge^ bridge_ = gcnew CallbackBridge();

        void RegisterCallbacks();
    };

    // Implementation
    // ------------------------------------------------------------------------

    inline Provider::Provider(System::Guid id)
    : provider_(ConvertGuid(id))
    {
        RegisterCallbacks();
    }

    inline Provider::Provider(String^ providerName)
    : provider_(msclr::interop::marshal_as<std::wstring>(providerName))
    {
        RegisterCallbacks();
    }

    inline void Provider::RegisterCallbacks() 
    {
        provider_->add_on_event_callback(bridge_->GetOnEventBridge());
        provider_->add_on_error_callback(bridge_->GetOnErrorBridge());
    }

} } } }