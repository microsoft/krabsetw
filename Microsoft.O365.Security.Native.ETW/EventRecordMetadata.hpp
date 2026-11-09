// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma once

#include <krabs.hpp>
#include "IEventRecordMetadata.hpp"
#include "Guid.hpp"

// Windows SDK may not define this constant on older SDK versions.
#ifndef EVENT_HEADER_EXT_TYPE_PROCESS_START_KEY
#define EVENT_HEADER_EXT_TYPE_PROCESS_START_KEY 0x000B
#endif

using namespace System;
using namespace System::Runtime::InteropServices;

namespace Microsoft { namespace O365 { namespace Security { namespace ETW {

    /// <summary>
    /// Concrete implementation representing the metadata about an ETW event record.
    /// </summary>
    /// <remarks>
    /// Instances are reused and valid only during their callback. Copy any values
    /// that must outlive the callback.
    /// </remarks>
    public ref class EventRecordMetadata : public IEventRecordMetadata
    {
    protected:
        const EVENT_RECORD* record_;
        const EVENT_HEADER* header_;
        uint64_t generation_ = 0;

        const EVENT_RECORD* CheckedRecord()
        {
            CheckValid();
            return record_;
        }

        const EVENT_HEADER* CheckedHeader()
        {
            CheckValid();
            return header_;
        }

    internal:
        void CheckValid()
        {
            if (record_ == nullptr)
                throw gcnew ObjectDisposedException("EventRecord");
        }

        void CheckValid(uint64_t generation)
        {
            CheckValid();
            if (generation != generation_)
                throw gcnew ObjectDisposedException("EventRecord");
        }

        property uint64_t Generation {
            uint64_t get() { return generation_; }
        }

        void Invalidate()
        {
            record_ = nullptr;
            header_ = nullptr;
        }

        EventRecordMetadata(const EVENT_RECORD& record)
            : record_(&record)
            , header_(&record.EventHeader) { }

        /// <summary>
        /// Updates this instance to point to the specified event record.
        /// </summary>
        void Update(const EVENT_RECORD& record)
        {
            ++generation_;
            record_ = &record;
            header_ = &record.EventHeader;
        }

    public:
        // For container ID's, we are expecting format "00000000-0000-0000-0000-0000000000000", 
        // 32 hex digits with 4 hyphens, no braces.
        static const size_t CONTAINER_ID_DATA_LENGTH_IN_BYTES = 36;

#pragma region EventDescriptor

        /// <summary>
        /// Retrieves the ID of this event.
        /// </summary>
        virtual property uint16_t Id
        {
            uint16_t get() { return CheckedHeader()->EventDescriptor.Id; }
        }

        /// <summary>
        /// Returns the opcode of this event.
        /// </summary>
        virtual property byte Opcode
        {
            virtual byte get() { return CheckedHeader()->EventDescriptor.Opcode; }
        }

        /// <summary>
        /// Returns the version of this event.
        /// </summary>
        virtual property byte Version
        {
            byte get() { return CheckedHeader()->EventDescriptor.Version; }
        }

        /// <summary>
        /// Returns the level of this event.
        /// </summary>
        virtual property byte Level
        {
            byte get() { return CheckedHeader()->EventDescriptor.Level; }
        }

#pragma endregion

#pragma region EventHeader

        /// <summary>
        /// Returns the flags of the event.
        /// </summary>
        virtual property uint16_t Flags
        {
            uint16_t get() { return CheckedHeader()->Flags; }
        }

        /// <summary>
        /// Returns the EventProperty of the event.
        /// </summary>
        virtual property EventHeaderProperty EventProperty
        {
            EventHeaderProperty get()
            {
                return (EventHeaderProperty)(CheckedHeader()->EventProperty);
            }
        }

        /// <summary>
        /// Retrieves the PID associated with the event.
        /// </summary>
        virtual property unsigned int ProcessId
        {
            unsigned int get() { return CheckedHeader()->ProcessId; }
        }

        /// <summary>
        /// Retrieves the Thread ID associated with the event.
        /// </summary>
        virtual property unsigned int ThreadId
        {
            unsigned int get() { return CheckedHeader()->ThreadId; }
        }

        /// <summary>
        /// Returns the timestamp associated with this event.
        /// </summary>
        virtual property DateTime Timestamp
        {
            DateTime get()
            {
                return DateTime::FromFileTimeUtc(CheckedHeader()->TimeStamp.QuadPart);
            }
        }

        /// <summary>
        /// Returns the Thread ID associated with the event.
        /// </summary>
        virtual property Guid ProviderId
        {
            Guid get() { return ConvertGuid(CheckedHeader()->ProviderId); }
        }

        /// <summary>
        /// Returns the Activity ID associated with the event.
        /// </summary>
        virtual property Guid ActivityId
        {
            Guid get() { return ConvertGuid(CheckedHeader()->ActivityId); }
        }

        /// <summary>
        /// Returns the type of the event record.
        /// DecodingSourceXMLFile - The event was emitted by a manifest-based provider.
        /// DecodingSourceWbem - The event was emitted by a MOF-based provider.
        /// DecodingSourceWPP - The event was emitted by a WPP software tracing provider.
        /// DecodingSourceTlg - The event was emitted by a TraceLogging provider.
        /// </summary>
        /// <returns>the type of the event record</returns>
        virtual DecodingSource GetEventType()
        {
            return (DecodingSource)krabs::get_event_type(*CheckedRecord());
        }

#pragma endregion

#pragma region EventRecord

        /// <summary>
        /// Returns the size in bytes of the UserData buffer.
        /// </summary>
        /// <returns>the size of the EVENT_RECORD.UserData buffer</returns>
        virtual property uint16_t UserDataLength
        {
            uint16_t get() { return CheckedRecord()->UserDataLength; }
        }

        /// <summary>
        /// Returns a pointer to the UserData buffer.
        /// </summary>
        /// <returns>a pointer to the EVENT_RECORD.UserData buffer</returns>
        virtual property IntPtr UserData
        {
            IntPtr get() { return IntPtr(CheckedRecord()->UserData); }
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

#pragma region ExtendedData

        /// <summary>
        /// If the event's extended data contains a Windows container ID (i.e. event came from inside
        /// a container using process isolation), retrieve it.
        /// Can be expensive, avoid calling more than once per event.
        /// </summary>
        /// <returns>
        /// True if a Guid was present. False if not. If a Guid was present, it will be written into the result 
        /// parameter. Throws a ContainerIdFormatException if the container ID is present but parsing fails.
        /// </returns>
        virtual bool TryGetContainerId([Out] System::Guid% result)
        {
            CheckValid();
            auto extended_data_count = record_->ExtendedDataCount;
            for (USHORT i = 0; i < extended_data_count; i++)
            {
                auto& extended_data = record_->ExtendedData[i];

                if (extended_data.ExtType == EVENT_HEADER_EXT_TYPE_CONTAINER_ID)
                {
                    try
                    {
                        // Convert to managed System::Guid for returning to managed code.
                        result = ConvertGuid(
                            krabs::guid_parser::parse_guid(
                                reinterpret_cast<char*>(extended_data.DataPtr),
                                extended_data.DataSize));
                    }
                    catch (const std::runtime_error& err)
                    {
                        // Convert to managed exception coming from managed function.
                        throw gcnew ContainerIdFormatException(gcnew System::String(err.what()));
                    }
                    
                    return true;
                }
            }

            // Not found.
            result = System::Guid::Empty;
            return false;
        }

        /// <summary>
        /// If the event's extended data contains a process start key
        /// (enabled via EVENT_ENABLE_PROPERTY_PROCESS_START_KEY), retrieve it.
        /// </summary>
        virtual bool TryGetProcessStartKey([Out] uint64_t% result)
        {
            CheckValid();
            auto extended_data_count = record_->ExtendedDataCount;
            for (USHORT i = 0; i < extended_data_count; i++)
            {
                auto& extended_data = record_->ExtendedData[i];

                if (extended_data.ExtType == EVENT_HEADER_EXT_TYPE_PROCESS_START_KEY)
                {
                    if (extended_data.DataPtr != 0)
                    {
                        result = *reinterpret_cast<const ULONG64*>(extended_data.DataPtr);
                        return true;
                    }
                }
            }

            result = 0;
            return false;
        }

#pragma endregion
    };

} } } }