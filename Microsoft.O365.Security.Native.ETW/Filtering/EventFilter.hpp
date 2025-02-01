// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma once

#include <krabs.hpp>

#include "../Callbacks.hpp"
#include "../Conversions.hpp"
#include "../Guid.hpp"
#include "../NativePtr.hpp"
#include "Predicate.hpp"

using namespace System;
using namespace System::Runtime::InteropServices;

namespace Microsoft { namespace O365 { namespace Security { namespace ETW {

    /// <summary>
    /// Allows for filtering an event in the native layer before it bubbles
    /// up to callbacks.
    /// </summary>
    public ref class EventFilter {
    public:

        /// <summary>
        /// Constructs an EventFilter with the given Predicate.
        /// </summary>
        /// <param name="predicate">the predicate to use to filter an event</param>
        EventFilter(O365::Security::ETW::Predicate ^predicate);

        /// <summary>
        /// Constructs an EventFilter with the given event ID.
        /// </summary>
        /// <param name="eventId">the event ID to filter using provider-based filtering</param>
        EventFilter(unsigned short eventId);

        /// <summary>
        /// Constructs an EventFilter with the given event ID and Predicate.
        /// </summary>
        /// <param name="eventId">the event ID to filter using provider-based filtering</param>
        /// <param name="predicate">the predicate to use to filter an event</param>
        EventFilter(unsigned short eventId, O365::Security::ETW::Predicate^ predicate);

        /// <summary>
        /// Constructs an EventFilter with the given event IDs.
        /// </summary>
        /// <param name="eventIds">the event IDs to filter using provider-based filtering</param>
        EventFilter(List<unsigned short>^ eventIds);

        /// <summary>
        /// Constructs an EventFilter with the given event IDs and Predicate.
        /// </summary>
        /// <param name="eventIds">the event IDs to filter using provider-based filtering</param>
        /// <param name="predicate">the predicate to use to filter an event</param>
        EventFilter(List<unsigned short>^ eventIds, O365::Security::ETW::Predicate^ predicate);

        /// <summary>
        /// An event that is invoked when an ETW event is fired on this
        /// filter and the event meets the given predicate.
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
        /// <summary>
        /// Allows implicit conversion to a krabs::event_filter.
        /// </summary>
        /// <returns>the native representation of an EventFilter</returns>
        operator krabs::event_filter&()
        {
            return *filter_;
        }

    internal:
        NativePtr<krabs::event_filter> filter_;
        CallbackBridge^ bridge_ = gcnew CallbackBridge();

        void RegisterCallbacks();
    };

    // Implementation
    // ------------------------------------------------------------------------

    EventFilter::EventFilter(O365::Security::ETW::Predicate ^pred)
    : filter_(pred->to_underlying())
    {
        RegisterCallbacks();
    }

    EventFilter::EventFilter(unsigned short eventId)
        : filter_(eventId)
    {
        RegisterCallbacks();
    }

    EventFilter::EventFilter(unsigned short eventId, O365::Security::ETW::Predicate^ pred)
    : filter_(eventId, pred->to_underlying())
    {
        RegisterCallbacks();
    }

    EventFilter::EventFilter(List<unsigned short>^ eventIds)
        : filter_(to_vector(eventIds))
    {
        RegisterCallbacks();
    }

    EventFilter::EventFilter(List<unsigned short>^ eventIds, O365::Security::ETW::Predicate^ pred)
        : filter_(to_vector(eventIds), pred->to_underlying())
    {
        RegisterCallbacks();
    }

    inline void EventFilter::RegisterCallbacks()
    {
        filter_->add_on_event_callback(bridge_->GetOnEventBridge());
        filter_->add_on_error_callback(bridge_->GetOnErrorBridge());
    }

} } } }