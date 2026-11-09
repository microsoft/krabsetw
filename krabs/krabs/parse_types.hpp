// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma once

#ifndef  WIN32_LEAN_AND_MEAN
#define  WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <sddl.h>

#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>
#include <type_traits>
#include <cstring>
#include <stdexcept>

#include "compiler_check.hpp"

namespace krabs {

    /**
     * <summary>
     *   Provided entirely for code clarity purposes.
     *   Indicates that the number is intended to be used as an ID
     * </summary>
     * <remarks>
     *   This should be turned into an _id user defined literal when our
     *   compiler decides to catch up to the times.
     * </remarks>
     * <example>
     *     id(1000);
     * </example>
     */
     template <typename T>
     T id(T n)
     {
        return n;
     }

    /**
     * <summary>
     *   Provided entirely for code clarity purposes.
     *   Indicates that the number is intended to be used as a version
     * </summary>
     * <remarks>
     *   This should be turned into a _vers user defined literal when our
     *   compiler decides to catch up to the times.
     * </remarks>
     * <example>
     *     id(1000);
     * </example>
     */
     template <typename T>
     T version(T n)
     {
        return n;
     }

    /**
     * <summary>
     *   Provided entirely for code clarity purposes.
     *   Indicates that the number is intended to be used as an opcode
     * </summary>
     * <remarks>
     *   This should be turned into a _opcode user defined literal when our
     *   compiler decides to catch up to the times.
     * </remarks>
     * <example>
     *     opcode(1000);
     * </example>
     */
     template <typename T>
     T opcode(T n)
     {
        return n;
     }


    /**
     * <summary>
     * Used to discriminate between hex ints and regular ints in ETW events.
     * </summary>
     * <remarks>
     * Q: Why in the world? I can't even.
     * A: ETW differentiates between hexints and regular ints. When
     *    record_builder validates that the input type matches the type
     *    specified in the schema, getting this wrong will cause an
     *    exception. A quick little type wrapper like this lets us
     *    discriminate based on the type and everything turns out better.
     * </remarks>
     */
    struct hexint32 {
        hexint32(int v)
        : value(v)
        {}

        int value;
    };

    struct hexint64 {
        hexint64(long long v)
        : value(v)
        {}

        long long value;
    };

    /**
     * <summary>
     * Used to support parsing and creation of binary ETW fields.
     * </summary>
     */
    struct binary {
    public:
        binary() : bytes_() { }

        binary(const BYTE* start, size_t n)
        : bytes_(start, start + n)
        { }

        const std::vector<BYTE>& bytes() const
        {
            return bytes_;
        }

    private:
        std::vector<BYTE> bytes_;
    };

    template<typename T>
    binary make_binary(const T& value, size_t n)
    {
        const auto start = (BYTE*)&value;
        return binary(start, n);
    }

    /**
     * <summary>
     * Used to handle parsing of IPv4 and IPv6 fields in an ETW record.
     * This is used in the parser class in a template specialization.
     * </summary>
     */
    struct ip_address {
        union {
            DWORD v4;
            BYTE v6[16];
        };
        bool is_ipv6;

        static ip_address from_ipv6(const BYTE* bytes)
        {
            ip_address addr;
            addr.is_ipv6 = true;
            memcpy_s(addr.v6, 16, bytes, 16);
            return addr;
        }

        static ip_address from_ipv4(DWORD val)
        {
            ip_address addr;
            addr.is_ipv6 = false;
            addr.v4 = val;
            return addr;
        }

        ip_address() {}
     };

    /**
    * <summary>
    * Used to handle parsing of socket addresses in
    * network order. This union is a convenient wrapper
    * around the type IPv4 and IPv6 types provided by
    * the Winsock (v2) APIs.
    * </summary>
    */
    struct socket_address {
        union {
            struct sockaddr sa;
            struct sockaddr_in sa_in;
            struct sockaddr_in6 sa_in6;
            struct sockaddr_storage sa_stor;
        };
        size_t size;

        static socket_address from_bytes(const BYTE* bytes, size_t size_in_bytes)
        {
            if (size_in_bytes == 1 || size_in_bytes > sizeof(sockaddr_storage) ||
                (bytes == nullptr && size_in_bytes != 0)) {
                throw std::runtime_error("Invalid socket address property length");
            }
            socket_address sa = {};
            if (size_in_bytes != 0)
                memcpy_s(&(sa.sa_stor), sizeof sa.sa_stor, bytes, size_in_bytes);
            sa.size = size_in_bytes;
            return sa;
        }
    };

    /**
     * <summary>
     * Holds information about an property extracted from the etw schema
     * </summary>
     */
    struct property_info {
        const BYTE *pPropertyIndex_;
        const EVENT_PROPERTY_INFO *pEventPropertyInfo_;
        ULONG length_;

        property_info(
            const BYTE *offset,
            const EVENT_PROPERTY_INFO &evtPropInfo,
            ULONG length)
            : pPropertyIndex_(offset)
            , pEventPropertyInfo_(&evtPropInfo)
            , length_(length)
        { }

        property_info()
            : pPropertyIndex_(nullptr)
            , pEventPropertyInfo_(nullptr)
            , length_(0)
        { }

        inline bool found() const
        {
            return pPropertyIndex_ != nullptr;
        }
    };

    /**
    * <summary>
    * Used to handle parsing of SIDs from either a
    * SID or WBEMSID property
    * </summary>
    */
    struct sid {
        // SIDs are variable-length
        // So the 'best' way to store them is to convert to a string
        // The other-end can either print the string or call ConvertStringSidToSidA
        // to get the SID back
        std::string sid_string;

        static sid from_bytes(const BYTE* bytes, size_t size_in_bytes)
        {
            // Formats the SID directly rather than via ConvertSidToStringSidA,
            // which costs a LocalAlloc/LocalFree and a copy per call, and which
            // trusts the SID's own sub-authority count rather than the size of
            // the property it was read from.
            //
            // Layout: Revision (1 byte), SubAuthorityCount (1 byte),
            // IdentifierAuthority (6 bytes, big-endian),
            // SubAuthority[SubAuthorityCount] (4 bytes each, little-endian).
            constexpr size_t header_size = 8;
            if (bytes == nullptr || size_in_bytes < header_size) {
                throw std::runtime_error("Failed to get a SID from a property");
            }

            const BYTE revision = bytes[0];
            const BYTE count = bytes[1];
            if (revision != SID_REVISION ||
                count > SID_MAX_SUB_AUTHORITIES ||
                size_in_bytes < header_size + count * sizeof(DWORD)) {
                throw std::runtime_error("Failed to get a SID from a property");
            }

            uint64_t authority = 0;
            for (size_t i = 2; i < header_size; ++i) {
                authority = (authority << 8) | bytes[i];
            }

            // "S-1-" + "0x" + 12 hex digits + 15 * ("-" + 10 digits) = 183
            char buffer[192];
            char* out = buffer;
            *out++ = 'S';
            *out++ = '-';
            *out++ = '1';
            *out++ = '-';
            out = append_authority(out, authority);
            for (BYTE i = 0; i < count; ++i) {
                DWORD sub_authority;
                memcpy(&sub_authority, bytes + header_size + i * sizeof(DWORD), sizeof(DWORD));
                *out++ = '-';
                out = append_decimal(out, sub_authority);
            }

            sid ws;
            ws.sid_string.assign(buffer, out);
            return ws;
        }

    private:
        static char* append_decimal(char* out, uint64_t value)
        {
            char digits[20];
            size_t n = 0;
            do {
                digits[n++] = static_cast<char>('0' + value % 10);
                value /= 10;
            } while (value != 0);
            while (n > 0) {
                *out++ = digits[--n];
            }
            return out;
        }

        static char* append_authority(char* out, uint64_t authority)
        {
            // Authorities that fit in 32 bits are written in decimal; larger
            // ones as 0x followed by uppercase hex without leading zeros.
            // Verified against ConvertSidToStringSid, which does not zero-pad
            // to 12 digits despite the 6-byte field.
            if (authority <= 0xFFFFFFFFull) {
                return append_decimal(out, authority);
            }

            static const char hex[] = "0123456789ABCDEF";
            *out++ = '0';
            *out++ = 'x';
            int shift = 44;
            while (((authority >> shift) & 0xF) == 0) {
                shift -= 4; // authority > 0xFFFFFFFF, so this stops by shift 32
            }
            for (; shift >= 0; shift -= 4) {
                *out++ = hex[(authority >> shift) & 0xF];
            }
            return out;
        }
    };

    /**
    * <summary>
    * Used to handle parsing of Pointer Address types.
    * </summary>
    */
    struct pointer {
        /**
        * We store the pointer as an uint64_t, as it is highly unlikley
        * to be pointing to somewhere accessible to our process
        */
        uint64_t address;

        static pointer from_bytes(const BYTE* bytes, size_t size_in_bytes)
        {
            pointer pt;

            // If 32-Bit, first parse as a uint32
            // Then we can 'cast' that to our uint64_t
            if (size_in_bytes == sizeof(uint32_t)) {
                pt.address = *reinterpret_cast<const uint32_t*>(bytes);
            }
            else if (size_in_bytes == sizeof(uint64_t)) {
                pt.address = *reinterpret_cast<const uint64_t*>(bytes);
            }
            else {
                throw std::runtime_error(
                    "Failed to get a POINTER from a property");
            }

            return pt;
        }

    private:
    };


    /**
     * <summary>
     * Used to handle parsing of CountedStrings in an ETW Record.
     * This is used in the parser class in a template specialization.
     * </summary>
     */
#pragma pack(push,1)
    struct counted_string {
        using value_type = wchar_t;
        using reference = value_type&;
        using pointer = value_type*;
        using const_reference = const value_type&;
        using const_pointer = const value_type*;
        using iterator = value_type*;
        using const_iterator = const value_type*;

        /**
         * size of the string in bytes
         */
        uint16_t size_;
        wchar_t string_[1];

        static const counted_string* from_bytes(const BYTE* bytes, size_t size_in_bytes)
        {
            if (bytes == nullptr || size_in_bytes < sizeof(uint16_t))
                throw std::runtime_error("Counted string header is incomplete");

            uint16_t count;
            std::memcpy(&count, bytes, sizeof(count));
            if (count % sizeof(value_type) != 0 ||
                count > size_in_bytes - sizeof(count))
                throw std::runtime_error("Counted string length exceeds property extent or is invalid");

            return reinterpret_cast<const counted_string*>(bytes);
        }

        const_pointer string() const
        {
            return string_;
        }

        size_t length() const
        {
            return size_ / sizeof(value_type);
        }
    };
#pragma pack(pop)

    static_assert(std::is_trivial<counted_string>::value && std::is_standard_layout<counted_string>::value , "Do not modify counted_string");

} /* namespace krabs */
