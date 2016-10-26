// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma once

#include <krabs.hpp>

#include "../EventRecordError.hpp"
#include "../EventRecord.hpp"
#include "../EventRecordMetadata.hpp"
#include "../Guid.hpp"
#include "../IEventRecord.hpp"
#include "../NativePtr.hpp"
#include "Predicate.hpp"

using namespace System;
using namespace System::Runtime::InteropServices;

namespace O365 { namespace Security { namespace ETW {

    /// <summary>
    /// Delegate called when a new ETW <see cref="O365::Security::ETW::EventRecord"/> is received.
    /// </summary>
    public delegate void IEventRecordDelegate(O365::Security::ETW::IEventRecord^ record);

    /// <summary>
    /// Delegate called on errors when processing an <see cref="O365::Security::ETW::EventRecord"/>.
    /// </summary>
    public delegate void EventRecordErrorDelegate(O365::Security::ETW::EventRecordError^ error);

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
        /// Destructs an EventFilter.
        /// </summary>
        ~EventFilter();

        /// <summary>
        /// An event that is invoked when an ETW event is fired on this
        /// filter and the event meets the given predicate.
        /// </summary>
        event IEventRecordDelegate^ OnEvent;

        /// <summary>
        /// An event that is invoked when an ETW event is received
        /// but an error occurs handling the record.
        /// </summary>
        event EventRecordErrorDelegate^ OnError;


    internal:
        /// <summary>
        /// Allows implicit conversion to a krabs::event_filter.
        /// </summary>
        /// <returns>the native representation of an EventFilter</returns>
        operator krabs::event_filter&()
        {
            return *filter_;
        }

        void EventNotification(const EVENT_RECORD &);

    internal:
        delegate void NativeHookDelegate(const EVENT_RECORD &);

        NativeHookDelegate ^del_;
        NativePtr<krabs::event_filter> filter_;
        GCHandle delegateHookHandle_;
        GCHandle delegateHandle_;
    };

    // Implementation
    // ------------------------------------------------------------------------

    EventFilter::EventFilter(O365::Security::ETW::Predicate ^pred)
    : filter_(pred->to_underlying())
    {
        del_ = gcnew NativeHookDelegate(this, &EventFilter::EventNotification);
        delegateHandle_ = GCHandle::Alloc(del_);
        auto bridged = Marshal::GetFunctionPointerForDelegate(del_);
        delegateHookHandle_ = GCHandle::Alloc(bridged);

        filter_->add_on_event_callback((krabs::c_provider_callback)bridged.ToPointer());
    }

    inline EventFilter::~EventFilter()
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

    inline void EventFilter::EventNotification(const EVENT_RECORD &record)
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
