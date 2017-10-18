// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma once

#include <krabs.hpp>

#include "EventRecord.hpp"
#include "EventRecordMetadata.hpp"
#include "Guid.hpp"
#include "NativePtr.hpp"
#include "Filtering/EventFilter.hpp"

using namespace System;
using namespace System::Runtime::InteropServices;

namespace O365 { namespace Security { namespace ETW {

    ref class UserTrace;

    // Flags as documented here:
    //  https://msdn.microsoft.com/en-us/library/windows/desktop/dd392306(v=vs.85).aspx
    public enum class UserTraceFlags
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
        IncludeProcessStartKey = 0x00000080
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
        /// Destructs a Provider.
        /// </summary>
        ~Provider();

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
        /// Represents the "level" value on the provider's options, where
        /// "level" determines events in what categories are 
        /// enabled for notification.
        /// </summary>
        property UserTraceFlags TraceFlags {
            void set(UserTraceFlags value) {
                provider_->trace_flags((UCHAR)value);
            }
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
        event IEventRecordDelegate^ OnEvent;

        /// <summary>
        /// An event that is invoked when an ETW event is received
        /// but an error occurs handling the record.
        /// </summary>
        event EventRecordErrorDelegate^ OnError;

    internal:
        void EventNotification(const EVENT_RECORD &);

    internal:
        delegate void NativeHookDelegate(const EVENT_RECORD &);

        NativeHookDelegate ^del_;
        NativePtr<krabs::provider<>> provider_;
        GCHandle delegateHookHandle_;
        GCHandle delegateHandle_;
        void SetUpProvider();
    };

    // Implementation
    // ------------------------------------------------------------------------

    inline Provider::Provider(System::Guid id)
    : provider_(ConvertGuid(id))
    {
        SetUpProvider();
    }

    inline Provider::Provider(String^ providerName)
    : provider_(msclr::interop::marshal_as<std::wstring>(providerName))
    {
        SetUpProvider();
    }

    inline void Provider::SetUpProvider() 
    {
        del_ = gcnew NativeHookDelegate(this, &Provider::EventNotification);
        delegateHandle_ = GCHandle::Alloc(del_);
        auto bridged = Marshal::GetFunctionPointerForDelegate(del_);
        delegateHookHandle_ = GCHandle::Alloc(bridged);

        provider_->add_on_event_callback((krabs::c_provider_callback)bridged.ToPointer());
    }

    inline Provider::~Provider()
    {
        if (delegateHandle_.IsAllocated)
        {
            delegateHandle_.Free();
        }

        if (delegateHookHandle_.IsAllocated)
        {
            delegateHookHandle_.Free();
        }
    }

    inline void Provider::EventNotification(const EVENT_RECORD &record)
    {
        try
        {
            krabs::schema schema(record);
            krabs::parser parser(schema);

            OnEvent(gcnew EventRecord(record, schema, parser));
        }
        catch (const krabs::could_not_find_schema& ex)
        {
            auto msg = gcnew String(ex.what());
            auto metadata = gcnew EventRecordMetadata(record);

            OnError(gcnew EventRecordError(msg, metadata));
        }
    }

} } }
