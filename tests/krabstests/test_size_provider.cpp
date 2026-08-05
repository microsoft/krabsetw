// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "CppUnitTest.h"
#include <krabs.hpp>

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace krabstests
{
    // These exercise krabs::size_provider directly, with hand-built schema metadata, so
    // they do not depend on any provider being registered on the machine. The equivalent
    // managed tests live in PropertySizerTests.cs.
    TEST_CLASS(test_size_provider)
    {
    public:

        TEST_METHOD(fixed_length_unicode_string_length_is_a_count_of_wchars)
        {
            // tdh.h, TDH_INTYPE_UNICODESTRING: "the epi.length field is the length of the
            // string in WCHARs". A schema that declares length 8 therefore describes 16
            // bytes, not 8.
            auto info = make_property(TDH_INTYPE_UNICODESTRING, TDH_OUTTYPE_STRING, 8);

            wchar_t payload[] = L"12345678";
            auto record = make_record(payload, sizeof(payload));

            Assert::AreEqual(
                (ULONG)16,
                krabs::size_provider::get_property_size(
                    (const BYTE*)payload, L"Property", record, info));
        }

        TEST_METHOD(fixed_length_ansi_string_length_is_a_count_of_bytes)
        {
            // tdh.h, TDH_INTYPE_ANSISTRING: the length is a count of BYTEs.
            auto info = make_property(TDH_INTYPE_ANSISTRING, TDH_OUTTYPE_STRING, 8);

            char payload[] = "12345678";
            auto record = make_record(payload, sizeof(payload));

            Assert::AreEqual(
                (ULONG)8,
                krabs::size_provider::get_property_size(
                    (const BYTE*)payload, L"Property", record, info));
        }

        TEST_METHOD(fixed_length_binary_length_is_a_count_of_bytes)
        {
            auto info = make_property(TDH_INTYPE_BINARY, TDH_OUTTYPE_HEXBINARY, 8);

            BYTE payload[8] = {};
            auto record = make_record(payload, sizeof(payload));

            Assert::AreEqual(
                (ULONG)8,
                krabs::size_provider::get_property_size(
                    payload, L"Property", record, info));
        }

        TEST_METHOD(pointer_size_comes_from_the_record_header)
        {
            auto info = make_property(TDH_INTYPE_POINTER, TDH_OUTTYPE_HEXINT64, 8);

            BYTE payload[8] = {};

            auto wide = make_record(payload, sizeof(payload));
            Assert::AreEqual(
                (ULONG)8,
                krabs::size_provider::get_property_size(payload, L"Property", wide, info));

            auto narrow = make_record(payload, sizeof(payload));
            narrow.EventHeader.Flags |= EVENT_HEADER_FLAG_32_BIT_HEADER;
            Assert::AreEqual(
                (ULONG)4,
                krabs::size_provider::get_property_size(payload, L"Property", narrow, info));
        }

        TEST_METHOD(null_terminated_unicode_string_is_measured_from_the_payload)
        {
            // No length in the schema, so the heuristic walks to the terminator and
            // includes it.
            auto info = make_property(TDH_INTYPE_UNICODESTRING, TDH_OUTTYPE_STRING, 0);

            wchar_t payload[] = L"abc";
            auto record = make_record(payload, sizeof(payload));

            Assert::AreEqual(
                (ULONG)8,
                krabs::size_provider::get_property_size(
                    (const BYTE*)payload, L"Property", record, info));
        }

        TEST_METHOD(unterminated_unicode_string_stops_at_the_end_of_the_record)
        {
            auto info = make_property(TDH_INTYPE_UNICODESTRING, TDH_OUTTYPE_STRING, 0);

            wchar_t payload[] = { L'a', L'b', L'c' };
            auto record = make_record(payload, sizeof(payload));

            Assert::AreEqual(
                (ULONG)6,
                krabs::size_provider::get_property_size(
                    (const BYTE*)payload, L"Property", record, info));
        }

    private:

        static EVENT_PROPERTY_INFO make_property(USHORT inType, USHORT outType, USHORT length)
        {
            EVENT_PROPERTY_INFO info = {};
            info.Flags = (PROPERTY_FLAGS)0;
            info.nonStructType.InType = inType;
            info.nonStructType.OutType = outType;
            info.length = length;
            info.count = 1;
            return info;
        }

        static EVENT_RECORD make_record(const void* userData, size_t userDataLength)
        {
            EVENT_RECORD record = {};
            record.UserData = const_cast<void*>(userData);
            record.UserDataLength = (USHORT)userDataLength;
            return record;
        }
    };
}
