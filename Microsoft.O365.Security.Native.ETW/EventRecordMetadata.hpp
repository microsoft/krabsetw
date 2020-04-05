// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma once

#include <krabs.hpp>
#include "IEventRecordMetadata.hpp"
#include "Guid.hpp"

using namespace System;
using namespace System::Runtime::InteropServices;

namespace Microsoft { namespace O365 { namespace Security { namespace ETW {

    /// <summary>
    /// Concrete implementation representing the metadata about an ETW event record.
    /// </summary>
    public ref class EventRecordMetadata : public IEventRecordMetadata
    {
    protected:
        const EVENT_RECORD* record_;
        const EVENT_HEADER* header_;

    internal:
        EventRecordMetadata(const EVENT_RECORD& record)
            : record_(&record)
            , header_(&record.EventHeader) { }

    public:
#pragma region EventDescriptor

        /// <summary>
        /// Retrieves the ID of this event.
        /// </summary>
        virtual property uint16_t Id
        {
            uint16_t get() { return header_->EventDescriptor.Id; }
        }

        /// <summary>
        /// Returns the opcode of this event.
        /// </summary>
        virtual property byte Opcode
        {
            virtual byte get() { return header_->EventDescriptor.Opcode; }
        }

        /// <summary>
        /// Returns the version of this event.
        /// </summary>
        virtual property byte Version
        {
            byte get() { return header_->EventDescriptor.Version; }
        }

        /// <summary>
        /// Returns the level of this event.
        /// </summary>
        virtual property byte Level
        {
            byte get() { return header_->EventDescriptor.Level; }
        }

#pragma endregion

#pragma region EventHeader

        /// <summary>
        /// Returns the flags of the event.
        /// </summary>
        virtual property uint16_t Flags
        {
            uint16_t get() { return header_->Flags; }
        }

        /// <summary>
        /// Returns the EventProperty of the event.
        /// </summary>
        virtual property EventHeaderProperty EventProperty
        {
            EventHeaderProperty get()
            {
                return (EventHeaderProperty)(header_->EventProperty);
            }
        }

        /// <summary>
        /// Retrieves the PID associated with the event.
        /// </summary>
        virtual property unsigned int ProcessId
        {
            unsigned int get() { return header_->ProcessId; }
        }

        /// <summary>
        /// Retrieves the Thread ID associated with the event.
        /// </summary>
        virtual property unsigned int ThreadId
        {
            unsigned int get() { return header_->ThreadId; }
        }

        /// <summary>
        /// Returns the timestamp associated with this event.
        /// </summary>
        virtual property DateTime Timestamp
        {
            DateTime get()
            {
                return DateTime::FromFileTimeUtc(header_->TimeStamp.QuadPart);
            }
        }

        /// <summary>
        /// Returns the Thread ID associated with the event.
        /// </summary>
        virtual property Guid ProviderId
        {
            Guid get() { return ConvertGuid(header_->ProviderId); }
        }

#pragma endregion

#pragma region EventRecord

        /// <summary>
        /// Returns the size in bytes of the UserData buffer.
        /// </summary>
        /// <returns>the size of the EVENT_RECORD.UserData buffer</returns>
        virtual property uint16_t UserDataLength
        {
            uint16_t get() { return record_->UserDataLength; }
        }

        /// <summary>
        /// Returns a pointer to the UserData buffer.
        /// </summary>
        /// <returns>a pointer to the EVENT_RECORD.UserData buffer</returns>
        virtual property IntPtr UserData
        {
            IntPtr get() { return IntPtr(record_->UserData); }
        }

        /// <summary>
        /// Marshals the event UserData onto the managed heap.
        /// </summary>
        /// <returns>a byte array representing the marshalled EVENT_RECORD.UserData buffer</returns>
        virtual array<uint8_t>^ CopyUserData()
        {
            auto dest = gcnew array<uint8_t>(UserDataLength);
            Marshal::Copy(UserData, dest, 0, UserDataLength);

            return dest;
        }

#pragma endregion
    };

} } } }