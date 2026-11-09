// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma once

#include "IEventRecordError.hpp"
#include "IEventRecordMetadata.hpp"

namespace Microsoft { namespace O365 { namespace Security { namespace ETW {

    /// <summary>
    /// Item passed to OnError handlers when an error is encountered
    /// handling an event on the worker thread.
    /// </summary>
    public ref struct EventRecordError : public IEventRecordError
    {
    private:
        System::String^ msg_;
        EventRecordMetadata^ record_;

    internal:
        EventRecordError(
            System::String^ message,
            EventRecordMetadata^ record)
            : msg_(message)
            , record_(record)
        { }

        /// <summary>
        /// Updates this instance to point to the specified event record.
        /// </summary>
        void Update(System::String^ msg, const EVENT_RECORD& record)
        {
            msg_ = msg;
            record_->Update(record);
        }

    public:
        /// <summary>
        /// Returns a string representing a message about the
        /// error that was encountered in the EventRecord.
        /// </summary>
        virtual property System::String^ Message {
            System::String^ get() {
                return msg_;
            }
        }

        /// <summary>
        /// Returns an object representing metadata about the
        /// record that was being processed when the error was
        /// encountered.
        /// </summary>
        virtual property IEventRecordMetadata^ Record {
            IEventRecordMetadata^ get() {
                return record_;
            }
        }
    };

} } } }