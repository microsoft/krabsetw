// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "CppUnitTest.h"
#include <krabs.hpp>

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace krabstests
{
    TEST_CLASS(test_size_provider)
    {
    public:
        TEST_METHOD(tdh_size_failure_is_not_accepted_as_an_empty_property)
        {
            BYTE payload[2] = {};
            auto record = make_record(payload, sizeof(payload));
            auto info = make_property(TDH_INTYPE_COUNTEDSTRING, 0);
            Assert::ExpectException<std::runtime_error>([&] {
                krabs::size_provider::get_property_size(payload, L"Value", record, info);
            });
        }

        TEST_METHOD(fixed_unicode_length_counts_wchars)
        {
            wchar_t payload[] = L"12345678";
            auto record = make_record(payload, sizeof(payload));
            auto info = make_property(TDH_INTYPE_UNICODESTRING, 8);
            Assert::AreEqual((ULONG)16, krabs::size_provider::get_property_size(
                (const BYTE*)payload, L"Value", record, info));

            auto metadata = make_metadata(info);
            krabs::event_layout layout(&metadata.info);
            Assert::AreEqual((ULONG)1, layout.first_dynamic(8));
            Assert::AreEqual((ULONG)1, layout.first_dynamic(4));
            Assert::AreEqual((ULONG)16, layout.fixed_offset(1, 8));
            Assert::AreEqual((ULONG)16, layout.fixed_offset(1, 4));
        }

        TEST_METHOD(fixed_ansi_length_counts_bytes)
        {
            char payload[] = "12345678";
            auto record = make_record(payload, sizeof(payload));
            auto info = make_property(TDH_INTYPE_ANSISTRING, 8);
            Assert::AreEqual((ULONG)8, krabs::size_provider::get_property_size(
                (const BYTE*)payload, L"Value", record, info));
        }

        TEST_METHOD(pointer_length_uses_the_emitting_width)
        {
            BYTE payload[8] = {};
            auto record = make_record(payload, sizeof(payload));
            auto info = make_property(TDH_INTYPE_POINTER, 8);
            Assert::AreEqual((ULONG)8, krabs::size_provider::get_property_size(
                payload, L"Value", record, info));
            record.EventHeader.Flags = EVENT_HEADER_FLAG_32_BIT_HEADER;
            Assert::AreEqual((ULONG)4, krabs::size_provider::get_property_size(
                payload, L"Value", record, info));
        }

        TEST_METHOD(struct_is_not_interpreted_as_a_scalar)
        {
            BYTE payload[16] = {};
            auto record = make_record(payload, sizeof(payload));
            auto info = make_property(TDH_INTYPE_UNICODESTRING, 4);
            info.Flags = PropertyStruct;
            Assert::ExpectException<std::runtime_error>([&] {
                krabs::size_provider::get_property_size(payload, L"Value", record, info);
            });

            auto metadata = make_metadata(info);
            krabs::event_layout layout(&metadata.info);
            Assert::AreEqual((ULONG)0, layout.first_dynamic(8));
            Assert::AreEqual((ULONG)0, layout.first_dynamic(4));
        }

    private:
        struct property_metadata {
            TRACE_EVENT_INFO info;
            wchar_t name[6];
        };

        static property_metadata make_metadata(const EVENT_PROPERTY_INFO& property)
        {
            property_metadata metadata = {};
            memcpy(metadata.name, L"Value", sizeof(metadata.name));
            metadata.info.PropertyCount = metadata.info.TopLevelPropertyCount = 1;
            metadata.info.EventPropertyInfoArray[0] = property;
            metadata.info.EventPropertyInfoArray[0].NameOffset =
                (ULONG)offsetof(property_metadata, name);
            return metadata;
        }

        static EVENT_PROPERTY_INFO make_property(USHORT type, USHORT length)
        {
            EVENT_PROPERTY_INFO info = {};
            info.nonStructType.InType = type;
            info.nonStructType.OutType = TDH_OUTTYPE_STRING;
            info.length = length;
            info.count = 1;
            return info;
        }

        static EVENT_RECORD make_record(void* data, USHORT length)
        {
            EVENT_RECORD record = {};
            record.UserData = data;
            record.UserDataLength = length;
            return record;
        }
    };
}
