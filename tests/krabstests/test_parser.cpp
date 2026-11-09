// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "CppUnitTest.h"
#include <krabs.hpp>

#include <sddl.h>

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace krabstests
{
    TEST_CLASS(test_parser)
    {
    public:

        TEST_METHOD(should_return_correct_count_of_props_when_enumerating)
        {
            krabs::guid powershell(L"{A0C1853B-5C40-4B15-8766-3CF1C58F985A}");
            krabs::testing::record_builder builder(powershell, krabs::id(7942), krabs::version(1));

            auto record = builder.pack_incomplete();
            krabs::schema schema(record, schema_locator_);
            krabs::parser parser(schema);

            // The number 8 here comes from the definition of the event in ETW -- we don't have control
            // of this.
            auto props = parser.properties();
            Assert::AreEqual((size_t)std::distance(props.begin(), props.end()), (size_t)8);
        }

#if NDEBUG
        TEST_METHOD(parse_should_not_throw_when_requesting_wrong_property_type_in_release)
        {
            krabs::guid powershell(L"{A0C1853B-5C40-4B15-8766-3CF1C58F985A}");
            krabs::testing::record_builder builder(powershell, krabs::id(7937), krabs::version(1));

            auto record = builder.pack_incomplete();
            krabs::schema schema(record, schema_locator_);
            krabs::parser parser(schema);

            // note, this would be a corrupted result
            parser.parse<std::string>(L"ContextInfo");
        }

        TEST_METHOD(try_parse_should_not_throw_when_requesting_wrong_property_type_in_release)
        {
            krabs::guid powershell(L"{A0C1853B-5C40-4B15-8766-3CF1C58F985A}");
            krabs::testing::record_builder builder(powershell, krabs::id(7937), krabs::version(1));

            auto record = builder.pack_incomplete();
            krabs::schema schema(record, schema_locator_);
            krabs::parser parser(schema);

            // note, this would be a corrupted result
            std::string result;
            Assert::IsTrue(parser.try_parse(L"ContextInfo", result));
        }

        TEST_METHOD(parse_should_throw_when_requesting_property_with_type_size_mismatch_in_release)
        {
            krabs::guid powershell(L"{A0C1853B-5C40-4B15-8766-3CF1C58F985A}");
            krabs::testing::record_builder builder(powershell, krabs::id(7937), krabs::version(1));

            auto record = builder.pack_incomplete();
            krabs::schema schema(record, schema_locator_);
            krabs::parser parser(schema);

            Assert::ExpectException<std::runtime_error>([&]() { parser.parse<int>(L"ContextInfo"); });
        }

        TEST_METHOD(try_parse_should_return_false_when_requesting_property_with_type_size_mismatch_in_release)
        {
            krabs::guid powershell(L"{A0C1853B-5C40-4B15-8766-3CF1C58F985A}");
            krabs::testing::record_builder builder(powershell, krabs::id(7937), krabs::version(1));

            auto record = builder.pack_incomplete();
            krabs::schema schema(record, schema_locator_);
            krabs::parser parser(schema);

            int result = 0;
            Assert::IsFalse(parser.try_parse(L"ContextInfo", result));
        }
#else
        TEST_METHOD(parse_should_throw_type_mismatch_when_requesting_property_with_wrong_type_in_debug)
        {
            krabs::guid powershell(L"{A0C1853B-5C40-4B15-8766-3CF1C58F985A}");
            krabs::testing::record_builder builder(powershell, krabs::id(7937), krabs::version(1));

            auto record = builder.pack_incomplete();
            krabs::schema schema(record, schema_locator_);
            krabs::parser parser(schema);

            Assert::ExpectException<krabs::type_mismatch_assert>([&]() { parser.parse<std::string>(L"ContextInfo"); });
        }

        TEST_METHOD(try_parse_should_throw_mismatch_when_requesting_property_of_wrong_type_in_debug)
        {
            krabs::guid powershell(L"{A0C1853B-5C40-4B15-8766-3CF1C58F985A}");
            krabs::testing::record_builder builder(powershell, krabs::id(7937), krabs::version(1));

            auto record = builder.pack_incomplete();
            krabs::schema schema(record, schema_locator_);
            krabs::parser parser(schema);

            std::string result;
            Assert::ExpectException<krabs::type_mismatch_assert>([&]() { parser.try_parse(L"ContextInfo", result); });
        }

        TEST_METHOD(parse_binary_should_return_field_bytes)
        {
            krabs::guid powershell(L"{A0C1853B-5C40-4B15-8766-3CF1C58F985A}");
            krabs::testing::record_builder builder(powershell, krabs::id(7937), krabs::version(1));
            builder.add_properties()(L"ContextInfo", L"Testing");

            auto record = builder.pack_incomplete();
            krabs::schema_locator schema_locator;
            krabs::schema schema(record, schema_locator);
            krabs::parser parser(schema);

            // note: binary doesn't type check
            auto data = parser.parse<krabs::binary>(L"ContextInfo");
            Assert::AreEqual((size_t)16, data.bytes().size());
            Assert::AreEqual((BYTE)'T', data.bytes()[0]);
        }
#endif

        TEST_METHOD(parse_unicode_string_should_work_when_unicode_string_property_is_last_and_not_null_terminated)
        {
            std::wstring expectedUrl(L"https://www.foo.com/api/v1/health/check");

            krabs::guid httpsys(L"{dd5ef90a-6398-47a4-ad34-4dcecdef795f}");
            // httpsys: parse event
            krabs::testing::record_builder builder(httpsys, krabs::id(2), 0U, 12, 1, true);
            builder.add_properties()
                (L"Url", expectedUrl);

            auto record = builder.pack_incomplete();
            krabs::schema schema(record, schema_locator_);
            krabs::parser parser(schema);

            auto url = parser.parse<std::wstring>(L"Url");

            Assert::AreEqual(expectedUrl, url);
        }

        TEST_METHOD(parse_unicode_string_should_work_when_unicode_string_property_is_last_and_not_null_terminated_when_previous_properties_were_parsed)
        {
            std::wstring expectedUrl;

            krabs::guid httpsys(L"{dd5ef90a-6398-47a4-ad34-4dcecdef795f}");
            // httpsys: parse event
            krabs::testing::record_builder builder(httpsys, krabs::id(2), 0U, 12, 1, true);
            builder.add_properties()
                (L"Url", expectedUrl);

            auto record = builder.pack_incomplete();
            krabs::schema schema(record, schema_locator_);
            krabs::parser parser(schema);

            auto requestobj = parser.parse<krabs::binary>(L"RequestObj");
            auto httpverb = parser.parse<krabs::binary>(L"HttpVerb");
            auto url = parser.parse<std::wstring>(L"Url");

            Assert::AreEqual(expectedUrl, url);
        }

        // Microsoft-Windows-Kernel-File Create_V1 (id 12, version 1):
        //   [0] Pointer Irp, [1] Pointer FileObject, [2] UInt32 IssuingThreadId,
        //   [3] UInt32 CreateOptions, [4] UInt32 CreateAttributes,
        //   [5] UInt32 ShareAccess, [6] UnicodeString FileName
        // Fixed-size properties first, then a payload-dependent one. Pointer
        // width shifts every fixed offset after the first two properties.

        TEST_METHOD(parse_should_return_same_values_regardless_of_access_order)
        {
            auto builder = kernel_file_create_builder();
            auto record = builder.pack_incomplete();
            krabs::schema schema(record, schema_locator_);

            krabs::parser in_order(schema);
            Assert::AreEqual(kernel_file_create_thread_id, in_order.parse<uint32_t>(L"IssuingThreadId"));
            Assert::AreEqual(kernel_file_create_share_access, in_order.parse<uint32_t>(L"ShareAccess"));
            Assert::AreEqual(kernel_file_create_file_name, in_order.parse<std::wstring>(L"FileName"));

            krabs::parser reversed(schema);
            Assert::AreEqual(kernel_file_create_file_name, reversed.parse<std::wstring>(L"FileName"));
            Assert::AreEqual(kernel_file_create_share_access, reversed.parse<uint32_t>(L"ShareAccess"));
            Assert::AreEqual(kernel_file_create_thread_id, reversed.parse<uint32_t>(L"IssuingThreadId"));
            Assert::AreEqual(kernel_file_create_file_object, reversed.parse<krabs::pointer>(L"FileObject").address);
        }

        TEST_METHOD(parse_should_return_correct_values_when_access_order_changes_between_events)
        {
            // The parser learns each event type's access order across events.
            // Readers with different orders sharing an event type must only
            // ever cost extra scanning, never change a result.
            auto builder = kernel_file_create_builder();
            auto record = builder.pack_incomplete();

            for (int i = 0; i < 3; ++i) {
                krabs::schema schema(record, schema_locator_);

                krabs::parser reversed(schema);
                Assert::AreEqual(kernel_file_create_file_name, reversed.parse<std::wstring>(L"FileName"));
                Assert::AreEqual(kernel_file_create_share_access, reversed.parse<uint32_t>(L"ShareAccess"));
                Assert::AreEqual(kernel_file_create_thread_id, reversed.parse<uint32_t>(L"IssuingThreadId"));

                krabs::parser single(schema);
                Assert::AreEqual(kernel_file_create_share_access, single.parse<uint32_t>(L"ShareAccess"));

                krabs::parser in_order(schema);
                Assert::AreEqual(kernel_file_create_file_object, in_order.parse<krabs::pointer>(L"FileObject").address);
                Assert::AreEqual(kernel_file_create_thread_id, in_order.parse<uint32_t>(L"IssuingThreadId", 0));
                Assert::AreEqual(kernel_file_create_file_name, in_order.parse<std::wstring>(L"FileName"));

                uint32_t missing = 0;
                Assert::IsFalse(in_order.try_parse(L"NoSuchProperty", missing));
                Assert::AreEqual(kernel_file_create_share_access, in_order.parse<uint32_t>(L"ShareAccess"));
            }
        }

        TEST_METHOD(parse_with_hint_should_return_correct_value_for_correct_wrong_and_out_of_range_hints)
        {
            auto builder = kernel_file_create_builder();
            auto record = builder.pack_incomplete();
            krabs::schema schema(record, schema_locator_);
            krabs::parser parser(schema);

            Assert::AreEqual(kernel_file_create_thread_id, parser.parse<uint32_t>(L"IssuingThreadId", 2));
            Assert::AreEqual(kernel_file_create_thread_id, parser.parse<uint32_t>(L"IssuingThreadId", 5));
            Assert::AreEqual(kernel_file_create_thread_id, parser.parse<uint32_t>(L"IssuingThreadId", 1000));
            Assert::AreEqual(kernel_file_create_file_name, parser.parse<std::wstring>(L"FileName", 0));

            uint32_t share = 0;
            Assert::IsTrue(parser.try_parse(L"ShareAccess", share, 6));
            Assert::AreEqual(kernel_file_create_share_access, share);
            Assert::IsFalse(parser.try_parse(L"NoSuchProperty", share, 3));
        }

        TEST_METHOD(parse_should_work_when_schema_is_constructed_without_schema_locator)
        {
            auto builder = kernel_file_create_builder();
            auto record = builder.pack_incomplete();
            krabs::schema schema(record, schema_locator_.get_event_schema(record));
            krabs::parser parser(schema);

            Assert::AreEqual(kernel_file_create_file_name, parser.parse<std::wstring>(L"FileName"));
            Assert::AreEqual(kernel_file_create_thread_id, parser.parse<uint32_t>(L"IssuingThreadId"));
            Assert::AreEqual(kernel_file_create_file_object, parser.parse<krabs::pointer>(L"FileObject").address);
        }

        TEST_METHOD(parse_should_use_event_pointer_size_when_schema_was_cached_from_other_pointer_size)
        {
            // Populate the cache from a 64-bit event...
            auto builder = kernel_file_create_builder();
            auto record64 = builder.pack_incomplete();
            {
                krabs::schema schema(record64, schema_locator_);
                krabs::parser parser(schema);
                Assert::AreEqual(kernel_file_create_thread_id, parser.parse<uint32_t>(L"IssuingThreadId"));
            }

            // ...then parse a 32-bit event of the same type using the same cache entry.
            std::vector<BYTE> payload;
            append(payload, uint32_t(0x11111111));               // Irp
            append(payload, uint32_t(kernel_file_create_file_object)); // FileObject
            append(payload, kernel_file_create_thread_id);       // IssuingThreadId
            append(payload, uint32_t(5));                        // CreateOptions
            append(payload, uint32_t(6));                        // CreateAttributes
            append(payload, kernel_file_create_share_access);    // ShareAccess
            const auto nameBytes = reinterpret_cast<const BYTE*>(kernel_file_create_file_name.c_str());
            payload.insert(payload.end(), nameBytes, nameBytes + (kernel_file_create_file_name.size() + 1) * sizeof(wchar_t));

            EVENT_RECORD record32 = {};
            record32.EventHeader = static_cast<const EVENT_RECORD&>(record64).EventHeader;
            record32.EventHeader.Flags = EVENT_HEADER_FLAG_32_BIT_HEADER;
            record32.UserData = payload.data();
            record32.UserDataLength = static_cast<USHORT>(payload.size());

            krabs::schema schema(record32, schema_locator_);
            krabs::parser parser(schema);
            Assert::AreEqual(kernel_file_create_share_access, parser.parse<uint32_t>(L"ShareAccess"));
            Assert::AreEqual(kernel_file_create_thread_id, parser.parse<uint32_t>(L"IssuingThreadId"));
            Assert::AreEqual(kernel_file_create_file_object, parser.parse<krabs::pointer>(L"FileObject").address);
            Assert::AreEqual(kernel_file_create_file_name, parser.parse<std::wstring>(L"FileName"));
        }

        TEST_METHOD(parse_should_throw_out_of_range_when_payload_ends_part_way_through_a_property)
        {
            auto builder = kernel_file_create_builder();
            auto packed = builder.pack_incomplete();
            EVENT_RECORD record = packed;
            // Irp, FileObject and IssuingThreadId (8 + 8 + 4 bytes), then half of CreateOptions.
            record.UserDataLength = 22;

            krabs::schema schema(record, schema_locator_);
            krabs::parser parser(schema);

            Assert::ExpectException<std::out_of_range>([&]() { parser.parse<uint32_t>(L"CreateOptions"); });
            Assert::ExpectException<std::out_of_range>([&]() { parser.parse<std::wstring>(L"FileName"); });
            Assert::AreEqual(kernel_file_create_thread_id, parser.parse<uint32_t>(L"IssuingThreadId"));
        }

#if NDEBUG
        // In debug builds, a payload that ends exactly at a property boundary with
        // more than one property left trips the parser's exhausted-payload assert.
        TEST_METHOD(parse_should_throw_out_of_range_for_properties_past_end_of_truncated_payload_in_release)
        {
            auto builder = kernel_file_create_builder();
            auto packed = builder.pack_incomplete();
            EVENT_RECORD record = packed;
            // Keep Irp, FileObject and IssuingThreadId (8 + 8 + 4 bytes) only.
            record.UserDataLength = 20;

            krabs::schema schema(record, schema_locator_);
            krabs::parser parser(schema);

            Assert::ExpectException<std::out_of_range>([&]() { parser.parse<std::wstring>(L"FileName"); });
            Assert::ExpectException<std::out_of_range>([&]() { parser.parse<uint32_t>(L"CreateOptions"); });
            Assert::AreEqual(kernel_file_create_thread_id, parser.parse<uint32_t>(L"IssuingThreadId"));

            uint32_t share = 0;
            Assert::IsFalse(parser.try_parse(L"ShareAccess", share));
        }
#endif

        TEST_METHOD(parse_should_work_when_many_properties_follow_a_payload_dependent_property)
        {
            // Microsoft-Windows-Kernel-Boot event 83 (version 0) has a string at
            // index 2 followed by ~58 more properties, so reaching the last one
            // walks more offsets than the parser keeps inline.
            krabs::guid kernelBoot(L"{15CA44FF-4D7A-4BAA-BBA5-0998955E531E}");
            krabs::testing::record_builder builder(kernelBoot, krabs::id(83), krabs::version(0));
            const uint64_t expected = 0x0123456789ABCDEF;
            builder.add_properties()
                (L"SystemRoot", std::wstring(L"C:\\Windows"))
                (L"UnlatchedUnsealPolicy->LKeyPkgId", expected);

            auto record = builder.pack_incomplete();
            krabs::schema schema(record, schema_locator_);
            krabs::parser parser(schema);

            Assert::AreEqual(expected, parser.parse<uint64_t>(L"UnlatchedUnsealPolicy->LKeyPkgId"));
            Assert::AreEqual(std::wstring(L"C:\\Windows"), parser.parse<std::wstring>(L"SystemRoot"));
        }

        TEST_METHOD(parse_sid_should_return_string_form_of_sid_property)
        {
            // Microsoft-Windows-Kernel-Process ProcessStart (version 3) carries the
            // process integrity level as a SID property.
            krabs::guid kernelProcess(L"{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}");
            krabs::testing::record_builder builder(kernelProcess, krabs::id(1), krabs::version(3));

            SID highIntegrity = { SID_REVISION, 1, SECURITY_MANDATORY_LABEL_AUTHORITY, SECURITY_MANDATORY_HIGH_RID };
            builder.add_properties()
                (L"MandatoryLabel", highIntegrity);

            auto record = builder.pack_incomplete();
            krabs::schema schema(record, schema_locator_);
            krabs::parser parser(schema);

            Assert::AreEqual(std::string("S-1-16-12288"), parser.parse<krabs::sid>(L"MandatoryLabel").sid_string);
        }

        TEST_METHOD(parse_sid_should_throw_when_sid_property_is_invalid)
        {
            krabs::guid kernelProcess(L"{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}");
            krabs::testing::record_builder builder(kernelProcess, krabs::id(1), krabs::version(3));

            SID badRevision = { SID_REVISION + 1, 1, SECURITY_MANDATORY_LABEL_AUTHORITY, SECURITY_MANDATORY_HIGH_RID };
            builder.add_properties()
                (L"MandatoryLabel", badRevision);

            auto record = builder.pack_incomplete();
            krabs::schema schema(record, schema_locator_);
            krabs::parser parser(schema);

            Assert::ExpectException<std::runtime_error>([&]() { parser.parse<krabs::sid>(L"MandatoryLabel"); });

            krabs::sid result;
            Assert::IsFalse(parser.try_parse(L"MandatoryLabel", result));
        }

        TEST_METHOD(parse_sid_should_skip_the_token_user_prefix_of_a_wbemsid)
        {
            // The kernel logger's classic MOF Process/Start (version 3) carries the
            // process owner as a WBEMSID: a TOKEN_USER followed by the SID.
            krabs::guid processClass(L"{3D6FA8D0-FE05-11D0-9DDA-00C04FD7BA7C}");
            krabs::testing::record_builder builder(processClass, krabs::id(0), krabs::version(3), krabs::opcode(1));
            builder.header().Flags = EVENT_HEADER_FLAG_CLASSIC_HEADER;

            const std::string expected = "S-1-5-21-3623811015-3361044348-30300820-1013";
            PSID sid = nullptr;
            Assert::IsTrue(ConvertStringSidToSidA(expected.c_str(), &sid) != FALSE);
            builder.add_properties()
                (L"UserSID", krabs::testing::wbemsid(sid))
                (L"ImageFileName", std::string("notepad.exe"));
            LocalFree(sid);

            auto record = builder.pack_incomplete();
            krabs::schema schema(record, schema_locator_);
            krabs::parser parser(schema);

            Assert::AreEqual(expected, parser.parse<krabs::sid>(L"UserSID").sid_string);
            Assert::AreEqual(std::string("notepad.exe"), parser.parse<std::string>(L"ImageFileName"));
        }

        // Heap Trace Provider HeapAlloc (classic MOF, version 2, opcode 33):
        //   Pointer HeapHandle, SizeT AllocSize, Pointer AllocAddress, UInt32 SourceId
        // Heap events are emitted in the bitness of the traced process, so a
        // WoW64 and a native process produce both widths of the same event,
        // and both share one cached schema.

        TEST_METHOD(parse_should_size_sizet_by_record_bitness_when_64_bit_record_is_cached_first)
        {
            krabs::guid heapTrace(L"{222962AB-6180-4B88-A825-346B75F2A24A}");

            krabs::testing::record_builder builder64(heapTrace, krabs::id(0), krabs::version(2), krabs::opcode(33));
            builder64.header().Flags = EVENT_HEADER_FLAG_CLASSIC_HEADER | EVENT_HEADER_FLAG_64_BIT_HEADER;
            builder64.add_properties()(L"SourceId", uint32_t(64));
            auto record64 = builder64.pack_incomplete();

            krabs::testing::record_builder builder32(heapTrace, krabs::id(0), krabs::version(2), krabs::opcode(33));
            builder32.header().Flags = EVENT_HEADER_FLAG_CLASSIC_HEADER | EVENT_HEADER_FLAG_32_BIT_HEADER;
            builder32.add_properties()(L"SourceId", uint32_t(32));
            auto record32 = builder32.pack_incomplete();

            krabs::schema schema64(record64, schema_locator_);
            krabs::parser parser64(schema64);
            Assert::AreEqual(size_t(8), parser64.parse<krabs::binary>(L"AllocSize").bytes().size());
            Assert::AreEqual(uint32_t(64), parser64.parse<uint32_t>(L"SourceId"));

            krabs::schema schema32(record32, schema_locator_);
            krabs::parser parser32(schema32);
            Assert::AreEqual(size_t(4), parser32.parse<krabs::binary>(L"AllocSize").bytes().size());
            Assert::AreEqual(uint32_t(32), parser32.parse<uint32_t>(L"SourceId"));
        }

        TEST_METHOD(parse_should_size_sizet_by_record_bitness_when_32_bit_record_is_cached_first)
        {
            krabs::guid heapTrace(L"{222962AB-6180-4B88-A825-346B75F2A24A}");

            krabs::testing::record_builder builder64(heapTrace, krabs::id(0), krabs::version(2), krabs::opcode(33));
            builder64.header().Flags = EVENT_HEADER_FLAG_CLASSIC_HEADER | EVENT_HEADER_FLAG_64_BIT_HEADER;
            builder64.add_properties()(L"SourceId", uint32_t(64));
            auto record64 = builder64.pack_incomplete();

            krabs::testing::record_builder builder32(heapTrace, krabs::id(0), krabs::version(2), krabs::opcode(33));
            builder32.header().Flags = EVENT_HEADER_FLAG_CLASSIC_HEADER | EVENT_HEADER_FLAG_32_BIT_HEADER;
            builder32.add_properties()(L"SourceId", uint32_t(32));
            auto record32 = builder32.pack_incomplete();

            krabs::schema schema32(record32, schema_locator_);
            krabs::parser parser32(schema32);
            Assert::AreEqual(size_t(4), parser32.parse<krabs::binary>(L"AllocSize").bytes().size());
            Assert::AreEqual(uint32_t(32), parser32.parse<uint32_t>(L"SourceId"));

            krabs::schema schema64(record64, schema_locator_);
            krabs::parser parser64(schema64);
            Assert::AreEqual(size_t(8), parser64.parse<krabs::binary>(L"AllocSize").bytes().size());
            Assert::AreEqual(uint32_t(64), parser64.parse<uint32_t>(L"SourceId"));
        }

        private:
            static constexpr uint32_t kernel_file_create_thread_id = 1234;
            static constexpr uint32_t kernel_file_create_share_access = 7;
            static constexpr uint64_t kernel_file_create_file_object = 0x22222222;
            const std::wstring kernel_file_create_file_name = L"C:\\krabs\\test.txt";

            krabs::testing::record_builder kernel_file_create_builder()
            {
                krabs::guid kernelFile(L"{EDD08927-9CC4-4E65-B970-C2560FB5C289}");
                krabs::testing::record_builder builder(kernelFile, krabs::id(12), krabs::version(1));
                builder.add_properties()
                    (L"FileObject", reinterpret_cast<void*>(kernel_file_create_file_object))
                    (L"IssuingThreadId", kernel_file_create_thread_id)
                    (L"ShareAccess", kernel_file_create_share_access)
                    (L"FileName", kernel_file_create_file_name);
                return builder;
            }

            template <typename T>
            static void append(std::vector<BYTE>& buffer, T value)
            {
                const auto bytes = reinterpret_cast<const BYTE*>(&value);
                buffer.insert(buffer.end(), bytes, bytes + sizeof(T));
            }

            krabs::schema_locator schema_locator_;
    };
}