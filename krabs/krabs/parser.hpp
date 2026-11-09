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
#include "schema_locator.hpp"
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
        property_info property_at(ULONG index);
        ULONG &dynamic_start(ULONG slot);
        ULONG find_index(std::wstring_view name, ULONG hint) const;
        const wchar_t *property_name(ULONG index) const;
#ifndef NDEBUG
        ULONG debug_start_of(ULONG index);
        ULONG debug_first_overrun(ULONG from) const;
#endif

    private:
        const schema &schema_;
        // Per-schema layout owned by the schema_locator. nullptr when the
        // schema was constructed from a bare TRACE_EVENT_INFO, in which case
        // names are scanned from the schema and every offset is walked.
        const event_layout *pLayout_;
        const BYTE *pData_;
        ULONG dataLength_;
        ULONG pointerSize_;
        ULONG firstDynamic_;
        // Where the next name scan starts: the explicit hint if one was given,
        // otherwise what the layout learned from previous events of this type.
        ULONG nextHint_;
        // Index of the previous successful lookup in this event, or
        // PropertyCount before the first one.
        ULONG lastIndex_;
        // Debug builds only: how far upstream's sequential walk would have got
        // (its lastPropertyIndex_), so its exhausted-payload assert fires on
        // exactly the same reads. Present in every build to keep the layout
        // identical; release builds never update it.
        ULONG debugWalked_;

        // Start offsets of properties firstDynamic_ onwards, discovered by
        // walking the payload on demand. Slot k holds the start of property
        // firstDynamic_ + k; resolvedSlots_ of them are known. Held inline
        // for the common case so constructing a parser does not allocate.
        static constexpr ULONG inline_slots = 16;
        ULONG resolvedSlots_;
        ULONG inlineStarts_[inline_slots];
        std::vector<ULONG> spillStarts_;
    };

    // Implementation
    // ------------------------------------------------------------------------

    inline parser::parser(const schema &s)
    : schema_(s)
    , pLayout_(s.pLayout_)
    , pData_((const BYTE*)s.record_.UserData)
    , dataLength_(s.record_.UserDataLength)
    , pointerSize_(size_provider::get_pointer_size(s.record_))
    , nextHint_(0)
    , lastIndex_(s.pSchema_->PropertyCount)
    , debugWalked_(0)
    {
        if (pLayout_ != nullptr) {
            nextHint_ = pLayout_->successor(lastIndex_);
            firstDynamic_ = pLayout_->first_dynamic(pointerSize_);
            // The first payload-dependent property still has a fixed start.
            inlineStarts_[0] = pLayout_->fixed_offset(firstDynamic_, pointerSize_);
        } else {
            firstDynamic_ = 0;
            inlineStarts_[0] = 0;
        }
        resolvedSlots_ = 1;
    }

    inline ULONG parser::find_index(std::wstring_view name, ULONG hint) const
    {
        if (pLayout_ != nullptr) {
            return pLayout_->find(name, hint);
        }

        const ULONG count = schema_.pSchema_->PropertyCount;
        if (hint >= count) hint = 0;
        for (ULONG n = 0; n < count; ++n) {
            const ULONG i = (hint + n) % count;
            if (name == property_name(i)) {
                return i;
            }
        }
        return count;
    }

    inline const wchar_t *parser::property_name(ULONG index) const
    {
        return reinterpret_cast<const wchar_t*>(
            reinterpret_cast<const BYTE*>(schema_.pSchema_) +
            schema_.pSchema_->EventPropertyInfoArray[index].NameOffset);
    }

    inline property_iterator parser::properties() const
    {
        return property_iterator(schema_);
    }

    inline property_info parser::find_property(std::wstring_view name)
    {
        return find_property(name, nextHint_);
    }

    inline property_info parser::find_property(std::wstring_view name, ULONG hint)
    {
        // A schema contains a collection of properties that are keyed by name.
        // These properties are stored in a blob of bytes that needs to be
        // interpreted according to information that is packaged up in the
        // schema and that can be retrieved using the Tdh* APIs.

        const ULONG totalPropCount = schema_.pSchema_->PropertyCount;
        if (totalPropCount == 0) {
            return property_info();
        }

        // Resolve property name to index via hinted linear scan.
        // ** This assumes that callers typically access properties in event order. **
        const ULONG index = find_index(name, hint);
        if (index >= totalPropCount) { // not found
            return property_info();
        }

        if (pLayout_ != nullptr) {
            // Remember this access order for the next event of this type.
            pLayout_->learn(lastIndex_, index);
            nextHint_ = pLayout_->successor(index);
        } else {
            nextHint_ = (index + 1) % totalPropCount;
        }
        lastIndex_ = index;

#ifdef NDEBUG
        return property_at(index);
#else
        // Upstream checked, before any lookup that had to walk forward, that a
        // payload which has run out leaves at most one property unread (a
        // trailing empty string whose null terminator the provider stripped).
        // Make the same check at the same points, against how far upstream's
        // walk would have got, so debug builds abort on exactly the same reads.
        if (index >= debugWalked_) {
            assert((debug_start_of(debugWalked_) == dataLength_
                        ? (totalPropCount - debugWalked_) <= 1
                        : true) &&
                   "invariant: if we've exhausted our buffer, then we must've"
                   "exhausted the properties as well");
        }
        try {
            auto info = property_at(index);
            if (index >= debugWalked_) {
                debugWalked_ = index + 1;
            }
            return info;
        }
        catch (const std::out_of_range&) {
            // Upstream's walk stops at the property that overran.
            debugWalked_ = debug_first_overrun(debugWalked_);
            throw;
        }
#endif
    }

#ifndef NDEBUG
    inline ULONG parser::debug_start_of(ULONG index)
    {
        // Start offset of a property upstream's walk has reached.
        if (pLayout_ != nullptr && index <= firstDynamic_) {
            return pLayout_->fixed_offset(index, pointerSize_);
        }
        return dynamic_start(index - firstDynamic_);
    }

    inline ULONG parser::debug_first_overrun(ULONG from) const
    {
        // First property at or after from that doesn't fit in the payload.
        for (ULONG k = from; k < firstDynamic_; ++k) {
            if (pLayout_->fixed_offset(k + 1, pointerSize_) > dataLength_) {
                return k;
            }
        }
        // Otherwise the walk failed on the property it was sizing.
        return firstDynamic_ + resolvedSlots_ - 1;
    }
#endif

    inline ULONG &parser::dynamic_start(ULONG slot)
    {
        if (slot < inline_slots) {
            return inlineStarts_[slot];
        }
        const ULONG spillIndex = slot - inline_slots;
        if (spillIndex >= spillStarts_.size()) {
            spillStarts_.resize(spillIndex + 1);
        }
        return spillStarts_[spillIndex];
    }

    inline property_info parser::property_at(ULONG index)
    {
        const auto &eventPropInfo = schema_.pSchema_->EventPropertyInfoArray[index];

        // Fast path: every property before the first payload-dependent one has
        // a start and size that are fixed by the schema.
        if (index < firstDynamic_) {
            const ULONG start = pLayout_->fixed_offset(index, pointerSize_);
            const ULONG end = pLayout_->fixed_offset(index + 1, pointerSize_);

            // Offsets are cumulative, so this also covers every property
            // before this one.
            if (end > dataLength_) {
                throw std::out_of_range("Property length past end of property buffer");
            }

            return property_info(pData_ + start, eventPropInfo, end - start);
        }

        // Slow path: walk the payload forward from the last property whose
        // start is known, remembering what we've seen to save time later.
        // The walk is lazy per-event -- we only walk forward to the
        // requested index, avoiding overhead when only a subset of
        // properties are needed.
        const ULONG slot = index - firstDynamic_;
        while (resolvedSlots_ <= slot + 1) {
            const ULONG current = firstDynamic_ + resolvedSlots_ - 1;
            const ULONG start = dynamic_start(resolvedSlots_ - 1);

            // A fixed-size prefix that overruns the payload means the
            // payload-dependent properties can't be located.
            if (start > dataLength_) {
                throw std::out_of_range("Property length past end of property buffer");
            }

            // accept that last property can be omitted from buffer. this happens if last property
            // is string but empty and the provider strips the null terminator
            const ULONG propertyLength = size_provider::get_property_size(
                                        pData_ + start,
                                        property_name(current),
                                        schema_.record_,
                                        schema_.pSchema_->EventPropertyInfoArray[current]);

            // verify that the length of the property doesn't exceed the buffer
            if (propertyLength > dataLength_ - start) {
                throw std::out_of_range("Property length past end of property buffer");
            }

            dynamic_start(resolvedSlots_) = start + propertyLength;
            resolvedSlots_++;
        }

        const ULONG start = dynamic_start(slot);
        return property_info(pData_ + start, eventPropInfo, dynamic_start(slot + 1) - start);
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

        return counted_string::from_bytes(propInfo.pPropertyIndex_, propInfo.length_);
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
            if (propInfo.length_ != 16)
                throw std::runtime_error("Invalid IPv6 property length");
            return ip_address::from_ipv6(propInfo.pPropertyIndex_);

        case TDH_OUTTYPE_IPV4:
            if (propInfo.length_ != sizeof(DWORD))
                throw std::runtime_error("Invalid IPv4 property length");
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
