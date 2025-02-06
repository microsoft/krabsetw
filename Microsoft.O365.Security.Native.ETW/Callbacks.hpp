// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma once

#include <krabs.hpp>

#include "EventRecord.hpp"
#include "EventRecordError.hpp"

using namespace System;
using namespace System::Runtime::InteropServices;

namespace Microsoft { namespace O365 { namespace Security { namespace ETW {

    /// <summary>
    /// Delegate called when a new ETW <see cref="O365::Security::ETW::EventRecord"/> is received.
    /// </summary>
    public delegate void IEventRecordDelegate(IEventRecord^ record);

    /// <summary>
    /// Delegate called when a new ETW <see cref="O365::Security::ETW::EventRecordMetadata"/> is received.
    /// </summary>
    public delegate void IEventRecordMetadataDelegate(IEventRecordMetadata^ record);

    /// <summary>
    /// Delegate called on errors when processing an <see cref="O365::Security::ETW::EventRecord"/>.
    /// </summary>
    public delegate void EventRecordErrorDelegate(IEventRecordError^ error);

    delegate void EventNativeDelegate(const EVENT_RECORD&, const krabs::trace_context&);

    delegate void EventErrorNativeDelegate(const EVENT_RECORD&, const std::string&);

    ref class CallbackBridge {
    private:

        EventNativeDelegate^ eventDelegateKeepAlive_;
        EventErrorNativeDelegate^ errorDelegateKeepAlive_;
        EventRecordMetadata^ metadata_;
        EventRecord^ record_;
        EventRecordError^ error_;

        EventRecordMetadata^ WrapMetadata(const EVENT_RECORD& record);
        EventRecord^ WrapRecord(const EVENT_RECORD& record, const krabs::schema& schema, krabs::parser& parser);
        EventRecordError^ WrapError(const std::string& error_message, const EVENT_RECORD& record);

        void EventNotification(const EVENT_RECORD& record, const krabs::trace_context& trace_context);
        void ErrorNotification(const EVENT_RECORD& record, const std::string& error_message);

    public:
        IEventRecordMetadataDelegate^ OnMetadata;
        IEventRecordDelegate^ OnEvent;
        EventRecordErrorDelegate^ OnError;

        krabs::c_provider_callback GetOnEventBridge()
        {
            if (!eventDelegateKeepAlive_)
                eventDelegateKeepAlive_ = gcnew EventNativeDelegate(this, &CallbackBridge::EventNotification);
            return (krabs::c_provider_callback)Marshal::GetFunctionPointerForDelegate(eventDelegateKeepAlive_).ToPointer();
        }

        krabs::c_provider_error_callback GetOnErrorBridge()
        {
            if (!errorDelegateKeepAlive_)
                errorDelegateKeepAlive_ = gcnew EventErrorNativeDelegate(this, &CallbackBridge::ErrorNotification);
            return (krabs::c_provider_error_callback)Marshal::GetFunctionPointerForDelegate(errorDelegateKeepAlive_).ToPointer();
        }
    };

    EventRecordMetadata^ CallbackBridge::WrapMetadata(const EVENT_RECORD& record)
    {
        auto value = metadata_;
        if (!value)
            return metadata_ = gcnew EventRecordMetadata(record);

        value->Update(record);
        return value;
    }

    EventRecord^ CallbackBridge::WrapRecord(const EVENT_RECORD& record, const krabs::schema& schema, krabs::parser& parser)
    {
        auto value = record_;
        if (!value) 
            return record_ = gcnew EventRecord(record, schema, parser);

        value->Update(record, schema, parser);
        return value;
    }

    EventRecordError^ CallbackBridge::WrapError(const std::string& error_message, const EVENT_RECORD& record)
    {
        auto msg = gcnew String(error_message.c_str());
        auto value = error_;
        if (!value)
            return error_ = gcnew EventRecordError(msg, gcnew EventRecordMetadata(record));

        value->Update(msg, record);
        return value;
    }

    void CallbackBridge::EventNotification(const EVENT_RECORD& record, const krabs::trace_context& trace_context)
    {
        auto onMetadata = OnMetadata;
        if (onMetadata) {
            auto metadata = WrapMetadata(record);

            onMetadata(metadata);
        }

        auto onEvent = OnEvent;
        if (onEvent) {
            TDHSTATUS status = ERROR_SUCCESS;
            trace_context.schema_locator.get_event_schema_no_throw(record, status);

            if (status == ERROR_SUCCESS) {
                krabs::schema schema(record, trace_context.schema_locator);
                krabs::parser parser(schema);
                auto evt = WrapRecord(record, schema, parser);

                onEvent(evt);
            }
            else {
                auto error_message = krabs::get_status_and_record_context(status, record);
                ErrorNotification(record, error_message);
            }
        }
    }

    void CallbackBridge::ErrorNotification(const EVENT_RECORD& record, const std::string& error_message)
    {
        auto onError = OnError;
        if (onError) {
            auto error = WrapError(error_message, record);

            onError(error);
        }
    }

    template<typename T>
    inline void CombineOrRemoveDelegate(T% target, T value, bool remove)
    {
        T original = target;
        T comparand;
        do
        {
            comparand = original;
            T newValue = remove ? (T)System::Delegate::Remove(original, value) : (T)System::Delegate::Combine(original, value);
            original = (T)System::Threading::Interlocked::CompareExchange(target, newValue, comparand);
        } while (original != comparand);
    }

    template<typename T>
    inline void CombineDelegate(T% target, T value)
    {
        CombineOrRemoveDelegate(target, value, false);
    }

    template<typename T>
    inline void RemoveDelegate(T% target, T value)
    {
        CombineOrRemoveDelegate(target, value, true);
    }

} } } }