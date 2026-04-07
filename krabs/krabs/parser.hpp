// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma once

#include <cassert>
#include <stdexcept>
#include <string_view>
#include <vector>

#include <functional>

#include "compiler_check.hpp"
#include "collection_view.hpp"
#include "property.hpp"
#include "parse_types.hpp"
#include "size_provider.hpp"
#include "tdh_helpers.hpp"

namespace krabs {

    class schema;

    /**
     * <summary>
     * Used to parse specific properties out of an event schema.
     * </summary>
     * <remarks>
     * The parser class dodges the task of trying to validate that the expected
     * type of a field matches the actual type of a field -- the onus is on
     * client code to get this right.
     * </remarks>
     */
    class parser {
    public:

        /**
         * <summary>
         * Constructs an event parser from an event schema.
         * </summary>
         * <example>
         *     void on_event(const EVENT_RECORD &record)
         *     {
         *         krabs::schema schema(record);
         *         krabs::parser parser(schema);
         *     }
         * </example>
         */
        parser(const schema &);

        /**
         * <summary>
         * Returns an iterator that returns each property in the event.
         * </summary>
         * <example>
         *    void on_event(const EVENT_RECORD &record)
         *    {
         *        krabs::schema schema(record);
         *        krabs::parser parser(schema);
         *        for (property &property : parser.properties())
         *        {
         *            // ...
         *        }
         *    }
         * </example>
         */
        property_iterator properties() const;

        /**
         * <summary>
         * Attempts to retrieve the given property by name and type.
         * </summary>
         * <remarks>
         * Type hinting here is taken as the authoritative source. There is no
         * validation that the request for type is correct.
         * </remarks>
         */
        template <typename T>
        bool try_parse(std::wstring_view name, T &out);

        /**
         * <summary>
         * Attempts to retrieve the given property by name and type,
         * starting the name scan at the given hint index.
         * </summary>
         */
        template <typename T>
        bool try_parse(std::wstring_view name, T &out, ULONG hint);

        /**
         * <summary>
         * Attempts to parse the given property by name and type. If the
         * property does not exist, an exception is thrown.
         * </summary>
         */
        template <typename T>
        T parse(std::wstring_view name);

        /**
         * <summary>
         * Attempts to parse the given property by name and type,
         * starting the name scan at the given hint index.
         * </summary>
         */
        template <typename T>
        T parse(std::wstring_view name, ULONG hint);

        template <typename Adapter>
        auto view_of(std::wstring_view name, Adapter &adapter) -> collection_view<typename Adapter::const_iterator>;

        template <typename Adapter>
        auto view_of(std::wstring_view name, ULONG hint, Adapter &adapter) -> collection_view<typename Adapter::const_iterator>;

    private:
        property_info find_property(std::wstring_view name);
        property_info find_property(std::wstring_view name, ULONG hint);
        void ensure_cache_populated();

    private:
        const schema &schema_;
        const BYTE *pEndBuffer_;

        // Fully populated on first access -- maps property index to its
        // location and size in the event's user-data blob.
        std::vector<property_info> propertyCache_;

        // Hint for name scan -- start from here on the next lookup.
        ULONG nextHint_;
    };

    // Implementation
    // ------------------------------------------------------------------------

    inline parser::parser(const schema &s)
    : schema_(s)
    , pEndBuffer_((BYTE*)s.record_.UserData + s.record_.UserDataLength)
    , nextHint_(0)
    {}

    inline property_iterator parser::properties() const
    {
        return property_iterator(schema_);
    }

    inline void parser::ensure_cache_populated()
    {
        if (!propertyCache_.empty()) {
            return;
        }

        const ULONG totalPropCount = schema_.pSchema_->PropertyCount;
        if (totalPropCount == 0) {
            return;
        }

        propertyCache_.reserve(totalPropCount);
        BYTE *pBuffer = (BYTE*)schema_.record_.UserData;

        for (ULONG i = 0; i < totalPropCount; ++i) {
            auto &currentPropInfo = schema_.pSchema_->EventPropertyInfoArray[i];
            const wchar_t *pName = reinterpret_cast<const wchar_t*>(
                                        reinterpret_cast<const BYTE*>(schema_.pSchema_) +
                                        currentPropInfo.NameOffset);

            ULONG propertyLength = size_provider::get_property_size(
                                        pBuffer,
                                        pName,
                                        schema_.record_,
                                        currentPropInfo);

            if (pBuffer + propertyLength > pEndBuffer_) {
                throw std::out_of_range("Property length past end of property buffer");
            }

            propertyCache_.emplace_back(pBuffer, currentPropInfo, propertyLength);
            pBuffer += propertyLength;
        }
    }

    inline property_info parser::find_property(std::wstring_view name)
    {
        return find_property(name, nextHint_);
    }

    inline property_info parser::find_property(std::wstring_view name, ULONG hint)
    {
        ensure_cache_populated();

        const ULONG totalPropCount = schema_.pSchema_->PropertyCount;
        if (totalPropCount == 0) {
            return property_info();
        }

        // Hinted linear scan. In the common case (sequential access
        // or caller-provided index) this hits on the first comparison.
        if (hint >= totalPropCount) {
            hint = 0;
        }

        ULONG index = totalPropCount; // sentinel = not found
        for (ULONG n = 0; n < totalPropCount; ++n) {
            ULONG i = (hint + n) % totalPropCount;
            auto &propInfo = schema_.pSchema_->EventPropertyInfoArray[i];
            const wchar_t *pName = reinterpret_cast<const wchar_t*>(
                reinterpret_cast<const BYTE*>(schema_.pSchema_) +
                propInfo.NameOffset);
            if (name == pName) {
                index = i;
                break;
            }
        }

        if (index >= totalPropCount) {
            return property_info();
        }

        nextHint_ = (index + 1) % totalPropCount;
        return propertyCache_[index];
    }

    inline void throw_if_property_not_found(const property_info &propInfo)
    {
        if (!propInfo.found()) {
            throw std::runtime_error("Property with the given name does not exist");
        }
    }

    template <typename T>
    size_t get_string_content_length(const T* string, size_t lengthBytes)
    {
        // for some string types the length includes the null terminator
        // so we need to find the length of just the content part

        T nullChar {0};
        auto length = lengthBytes / sizeof(T);

        for (auto i = length; i >= 1; --i)
            if (string[i - 1] != nullChar) return i;

        return 0;
    }

    // try_parse
    // ------------------------------------------------------------------------

    template <typename T>
    bool parser::try_parse(std::wstring_view name, T &out, ULONG hint)
    {
        nextHint_ = hint;
        return try_parse(name, out);
    }

    template <typename T>
    bool parser::try_parse(std::wstring_view name, T &out)
    {
        try {
            out = parse<T>(name);
            return true;
        }

#ifndef NDEBUG
        // in debug builds we want any mismatch asserts
        // to get back to the caller. This is removed
        // in release builds.
        catch (const krabs::type_mismatch_assert&) {
            throw;
        }
#endif // NDEBUG

        catch (...) {
            return false;
        }
    }

    // parse
    // ------------------------------------------------------------------------

    template <typename T>
    T parser::parse(std::wstring_view name, ULONG hint)
    {
        nextHint_ = hint;
        return parse<T>(name);
    }

    template <typename T>
    T parser::parse(std::wstring_view name)
    {
        auto propInfo = find_property(name);
        throw_if_property_not_found(propInfo);

        krabs::debug::assert_valid_assignment<T>(name, propInfo);

        // ensure that size of the type we are requesting is
        // the same size of the property in the event
        if (sizeof(T) != propInfo.length_)
            throw std::runtime_error("Property size doesn't match requested size");

        return *(T*)propInfo.pPropertyIndex_;
    }

    template<>
    inline bool parser::parse<bool>(std::wstring_view name)
    {
        auto propInfo = find_property(name);
        throw_if_property_not_found(propInfo);

        krabs::debug::assert_valid_assignment<bool>(name, propInfo);

        // Boolean in ETW is 4 bytes long
        return static_cast<bool>(*(unsigned*)propInfo.pPropertyIndex_);
    }

    template <>
    inline std::wstring parser::parse<std::wstring>(std::wstring_view name)
    {
        auto propInfo = find_property(name);
        throw_if_property_not_found(propInfo);

        krabs::debug::assert_valid_assignment<std::wstring>(name, propInfo);

        auto string = reinterpret_cast<const wchar_t*>(propInfo.pPropertyIndex_);
        auto length = get_string_content_length(string, propInfo.length_);

        return std::wstring(string, length);
    }

    template <>
    inline std::string parser::parse<std::string>(std::wstring_view name)
    {
        auto propInfo = find_property(name);
        throw_if_property_not_found(propInfo);

        krabs::debug::assert_valid_assignment<std::string>(name, propInfo);

        auto string = reinterpret_cast<const char*>(propInfo.pPropertyIndex_);
        auto length = get_string_content_length(string, propInfo.length_);

        return std::string(string, length);
    }

    template<>
    inline const counted_string* parser::parse<const counted_string*>(std::wstring_view name)
    {
        auto propInfo = find_property(name);
        throw_if_property_not_found(propInfo);

        krabs::debug::assert_valid_assignment<const counted_string*>(name, propInfo);

        return reinterpret_cast<const counted_string*>(propInfo.pPropertyIndex_);
    }

    template<>
    inline binary parser::parse<binary>(std::wstring_view name)
    {
        auto propInfo = find_property(name);
        throw_if_property_not_found(propInfo);

        // no type asserts for binary - anything can be read as binary

        return binary(propInfo.pPropertyIndex_, propInfo.length_);
    }

    template<>
    inline ip_address parser::parse<ip_address>(
        std::wstring_view name)
    {
        auto propInfo = find_property(name);
        throw_if_property_not_found(propInfo);

        krabs::debug::assert_valid_assignment<ip_address>(name, propInfo);

        auto outType = propInfo.pEventPropertyInfo_->nonStructType.OutType;

        switch (outType) {
        case TDH_OUTTYPE_IPV6:
            return ip_address::from_ipv6(propInfo.pPropertyIndex_);

        case TDH_OUTTYPE_IPV4:
            return ip_address::from_ipv4(*(DWORD*)propInfo.pPropertyIndex_);

        default:
            throw std::runtime_error("IP Address was not IPV4 or IPV6");
        }
    }

    template<>
    inline socket_address parser::parse<socket_address>(
        std::wstring_view name)
    {
        auto propInfo = find_property(name);
        throw_if_property_not_found(propInfo);

        krabs::debug::assert_valid_assignment<socket_address>(name, propInfo);

        return socket_address::from_bytes(propInfo.pPropertyIndex_, propInfo.length_);
    }

    template<>
    inline sid parser::parse<sid>(
        std::wstring_view name)
    {
        auto propInfo = find_property(name);
        throw_if_property_not_found(propInfo);

        krabs::debug::assert_valid_assignment<sid>(name, propInfo);
        auto InType = propInfo.pEventPropertyInfo_->nonStructType.InType;

        // A WBEMSID is actually a TOKEN_USER structure followed by the SID.
        // We only care about the SID. From MSDN:
        //
        //      The size of the TOKEN_USER structure differs
        //      depending on whether the events were generated on a 32 - bit
        //      or 64 - bit architecture. Also the structure is aligned
        //      on an 8 - byte boundary, so its size is 8 bytes on a
        //      32 - bit computer and 16 bytes on a 64 - bit computer.
        //      Doubling the pointer size handles both cases.
        ULONG sid_start = 16;
        if (EVENT_HEADER_FLAG_32_BIT_HEADER == (schema_.record_.EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER)) {
            sid_start = 8;
        }
        switch (InType) {
        case TDH_INTYPE_SID:
            return sid::from_bytes(propInfo.pPropertyIndex_, propInfo.length_);
        case TDH_INTYPE_WBEMSID:
            // Safety measure to make sure we don't overflow
            if (propInfo.length_ <= sid_start) {
                throw std::runtime_error(
                    "Requested a WBEMSID property but data is too small");
            }
            return sid::from_bytes(propInfo.pPropertyIndex_ + sid_start, propInfo.length_ - sid_start);

        default:
            throw std::runtime_error("SID was not a SID or WBEMSID");
        }
    }

    template<>
    inline pointer parser::parse<pointer>(std::wstring_view name)
    {
        auto propInfo = find_property(name);
        throw_if_property_not_found(propInfo);

        krabs::debug::assert_valid_assignment<pointer>(name, propInfo);

        return pointer::from_bytes(propInfo.pPropertyIndex_, propInfo.length_);
    }

    // view_of
    // ------------------------------------------------------------------------

    template <typename Adapter>
    auto parser::view_of(std::wstring_view name, ULONG hint, Adapter &adapter)
        -> collection_view<typename Adapter::const_iterator>
    {
        nextHint_ = hint;
        return view_of(name, adapter);
    }

    template <typename Adapter>
    auto parser::view_of(std::wstring_view name, Adapter &adapter)
        -> collection_view<typename Adapter::const_iterator>
    {
        auto propInfo = find_property(name);
        throw_if_property_not_found(propInfo);

        // TODO: type asserts?

        return adapter(propInfo);
    }
}
