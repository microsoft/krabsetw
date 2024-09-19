// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma once

#ifndef  WIN32_LEAN_AND_MEAN
#define  WIN32_LEAN_AND_MEAN
#endif

#define INITGUID

#include <windows.h>
#include <tdh.h>
#include <evntrace.h>

#include <memory>
#include <unordered_map>

#include "compiler_check.hpp"
#include "errors.hpp"
#include "guid.hpp"

#pragma comment(lib, "tdh.lib")

namespace krabs {

    /**
     * <summary>
     * Type used as the key for cache lookup in a schema_locator.
     * </summary>
     */
    struct schema_key
    {
        guid      provider;

        /**
         * Using a string_view for name so that keys can be constructed from
         * EVENT_RECORD pointers without allocation. If the key instance is
         * added to the cache, 'internalize_name' must be called first so that
         * the name points to owned memory and doesn't dangle.
         * Only events logged with the TraceLogger API will have a name set
         * in the key because it's available as part of the EVENT_RECORD.
         * Other events are uniquely distinguished by their event Id.
         */
        std::string_view name;

        uint16_t  id;
        uint8_t   version;
        uint8_t   opcode;
        uint8_t   level;
        uint64_t  keyword;

    private:
        /**
         * See note on 'name', this is only set when internalized and
         * provides memory ownership for the string_view.
         */
        std::unique_ptr<std::string> backing_name;

    public:
        schema_key(const EVENT_RECORD &record, std::string_view name)
            : provider(record.EventHeader.ProviderId)
            , name(name)
            , id(record.EventHeader.EventDescriptor.Id)
            , version(record.EventHeader.EventDescriptor.Version)
            , opcode(record.EventHeader.EventDescriptor.Opcode)
            , level(record.EventHeader.EventDescriptor.Level)
            , keyword(record.EventHeader.EventDescriptor.Keyword) { }

        schema_key(const schema_key &rhs)
            : provider(rhs.provider)
            , name(rhs.name)
            , id(rhs.id)
            , version(rhs.version)
            , opcode(rhs.opcode)
            , level(rhs.level)
            , keyword(rhs.keyword)
        {
            internalize_name();
        }

        schema_key& operator=(const schema_key &rhs)
        {
            schema_key temp(rhs);
            std::swap(*this, temp);
            return *this;
        }

        bool operator==(const schema_key &rhs) const
        {
            // NB: Compare 'name' last for perf. Do not compare 'backing_name'.
            return provider == rhs.provider &&
                   id == rhs.id &&
                   version == rhs.version &&
                   opcode == rhs.opcode &&
                   level == rhs.level &&
                   keyword == rhs.keyword &&
                   name == rhs.name;
        }

        bool operator!=(const schema_key &rhs) const { return !(*this == rhs); }

        /**
         * <summary>
         * Allocate the 'backing_name' and set 'name' to point at it. This must be
         * called before adding the key to a cache so that the lifetime of the
         * 'name' string_view matches the lifetime of the cached instance.
         * </summary>
         */
        void internalize_name()
        {
            if (!name.empty()) {
                backing_name = std::make_unique<std::string>(name);
                name = *backing_name;
            }
        }
    };
}

namespace std {

    /**
     * <summary>
     * Builds a hash code for a schema_key
     * </summary>
     */
    template<>
    struct std::hash<krabs::schema_key>
    {
        size_t operator()(const krabs::schema_key &key) const
        {
            // Shift-Add-XOR hash - good enough for the small sets we deal with
            size_t h = 2166136261;

            h ^= (h << 5) + (h >> 2) + std::hash<krabs::guid>()(key.provider);
            h ^= (h << 5) + (h >> 2) + std::hash<std::string_view>()(key.name);
            h ^= (h << 5) + (h >> 2) + key.id;
            h ^= (h << 5) + (h >> 2) + key.version;
            h ^= (h << 5) + (h >> 2) + key.opcode;
            h ^= (h << 5) + (h >> 2) + key.level;
            h ^= (h << 5) + (h >> 2) + key.keyword;

            return h;
        }
    };
}

namespace krabs {

    /**
     * <summary>
     * Get event schema from TDH.
     * </summary>
     */
    std::unique_ptr<char[]> get_event_schema_from_tdh(const EVENT_RECORD &);

    /**
     * <summary>
     * Returns a string_view to the event name if the specified event was logged
     * with the TraceLogger API otherwise returns an empty string_view.
     * </summary>
     */
    std::string_view get_trace_logger_event_name(const EVENT_RECORD &);

    /**
     * <summary>
     * Fetches and caches schemas from TDH.
     * NOTE: this cache also reduces the number of managed to native transitions
     * when krabs is compiled into a managed assembly.
     * </summary>
     */
    class schema_locator {
    public:

        /**
         * <summary>
         * Retrieves the event schema from the cache or falls back to
         * TDH to load the schema.
         * </summary>
         */
        const PTRACE_EVENT_INFO get_event_schema(const EVENT_RECORD &record) const;

    private:
        mutable std::unordered_map<schema_key, std::unique_ptr<char[]>> cache_;
    };

    // Implementation
    // ------------------------------------------------------------------------

    inline std::string_view get_trace_logger_event_name(const EVENT_RECORD & record)
    {
        /**
         * This implements part of the parsing that TDH would normally do so that
         * a schema_key can be built without calling TDH (which is expensive).
         * Here's pseudo code from the TraceLogger header describing the layout.
         *
         * // EventMetadata:
         * // This pseudo-structure is the layout of the "event metadata" referenced by
         * // EVENT_DATA_DESCRIPTOR_TYPE_EVENT_METADATA.
         * // It provides the event's name, event tags, and field information.
         * struct EventMetadata // Variable-length pseudo-structure, byte-aligned, tightly-packed.
         * {
         *     UINT16 Size; // = sizeof(EventMetadata)
         *     UINT8 Extension[]; // 1 or more bytes. Read until you hit a byte with high bit unset.
         *     char Name[]; // UTF-8 nul-terminated event name
         *     FieldMetadata Fields[]; // 0 or more field definitions.
         * };
         */

        char* metadataPtr = nullptr;
        USHORT metadataSize = 0;

        // Look for a TraceLogger event schema in the extended data.
        for (USHORT i = 0; i < record.ExtendedDataCount; ++i) {
            auto& dataItem = record.ExtendedData[i];
            if (dataItem.ExtType == EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL) {
                metadataSize = dataItem.DataSize;
                metadataPtr = (char*)dataItem.DataPtr;
                break;
            }
        }

        // Didn't find one or it was too small.
        if (metadataPtr == nullptr || metadataSize < sizeof(USHORT)) {
            return {};
        }

        // Ensure that the sizes match to prevent reading off the buffer.
        USHORT structSize = *(USHORT*)metadataPtr;
        if (structSize != metadataSize) {
            return {};
        }

        // Skipping over the 'Extension' field of the block to find the name offset.
        // Per code comment: Read until you hit a byte with high bit unset.
        USHORT nameOffset = sizeof(USHORT);
        while (nameOffset < structSize) {
            char c = *(metadataPtr + nameOffset);
            nameOffset++; // NB: always consume the character.

            // High-bit set?
            if ((c & 0x80) != 0x80) {
                break;
            }
        }

        // Ensure the offset found is valid.
        if (nameOffset >= structSize) {
            return {};
        }

        return {metadataPtr + nameOffset};
    }

    inline const PTRACE_EVENT_INFO schema_locator::get_event_schema(const EVENT_RECORD &record) const
    {
        auto eventName = get_trace_logger_event_name(record);
        auto key = schema_key(record, eventName);

        // Check the cache...
        auto it = cache_.find(key);
        if (it != cache_.end()) {
            return (PTRACE_EVENT_INFO)it->second.get();
        }

        // Cache miss. Fetch the schema...
        auto buffer = get_event_schema_from_tdh(record);
        auto returnVal = (PTRACE_EVENT_INFO)buffer.get();

        // Add the new instance to the cache.
        // NB: key's 'internalize_name' gets called by the cctor here.
        cache_.emplace(key, std::move(buffer));

        return returnVal;
    }

    inline std::unique_ptr<char[]> get_event_schema_from_tdh(const EVENT_RECORD &record)
    {
        // get required size
        ULONG bufferSize = 0;
        ULONG status = TdhGetEventInformation(
            (PEVENT_RECORD)&record,
            0,
            NULL,
            NULL,
            &bufferSize);

        if (status != ERROR_INSUFFICIENT_BUFFER) {
            error_check_common_conditions(status, record);
        }

        // allocate and fill the schema from TDH
        auto buffer = std::unique_ptr<char[]>(new char[bufferSize]);

        error_check_common_conditions(
            TdhGetEventInformation(
            (PEVENT_RECORD)&record,
            0,
            NULL,
            (PTRACE_EVENT_INFO)buffer.get(),
            &bufferSize),
            record);

        return buffer;
    }
}
