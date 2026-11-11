// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "CppUnitTest.h"
#include <krabs.hpp>

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace krabstests
{
    TEST_CLASS(test_record_builder)
    {
    public:
        TEST_METHOD(unfilled_pointer_and_empty_sized_strings_preserve_the_next_scalar)
        {
            for (auto flags : { EVENT_HEADER_FLAG_32_BIT_HEADER, EVENT_HEADER_FLAG_64_BIT_HEADER }) {
                krabs::guid wininet(L"{43D1A55C-76D6-4F7E-995C-64C711E5CAFE}");
                krabs::testing::record_builder builder(wininet, 101, 0);
                builder.header().Flags = (USHORT)flags;
                builder.add_properties()(L"Flags", (uint32_t)0x12345678);
                auto record = builder.pack_incomplete();
                krabs::schema schema(record, schema_locator_);
                krabs::parser parser(schema);
                Assert::AreEqual((uint32_t)0x12345678, parser.parse<uint32_t>(L"Flags"));
            }
        }

        TEST_METHOD(sized_unicode_string_has_no_extra_terminator)
        {
            krabs::guid wininet(L"{43D1A55C-76D6-4F7E-995C-64C711E5CAFE}");
            krabs::testing::record_builder builder(wininet, 404, 0);
            builder.add_properties()(L"TruncatedLength", (uint16_t)3)
                (L"TruncatedData", std::wstring(L"a\0b", 3));
            auto packed = builder.pack_incomplete();
            const EVENT_RECORD& record = packed;
            Assert::AreEqual((unsigned)32, (unsigned)record.UserDataLength);
            krabs::schema schema(record, schema_locator_);
            krabs::parser parser(schema);
            Assert::AreEqual(std::wstring(L"a\0b", 3), parser.parse<std::wstring>(L"TruncatedData"));
        }

        TEST_METHOD(sized_binary_rejects_a_mismatched_payload_length)
        {
            krabs::guid wininet(L"{43D1A55C-76D6-4F7E-995C-64C711E5CAFE}");
            krabs::testing::record_builder builder(wininet, 414, 0);
            BYTE bytes[] = { 0xA1, 0xB2 };
            builder.add_properties()(L"PayloadByteLength", (uint32_t)3)
                (L"Payload", krabs::binary(bytes, sizeof(bytes)));
            Assert::ExpectException<std::invalid_argument>([&] { builder.pack_incomplete(); });
        }

        TEST_METHOD(sized_binary_preserves_the_declared_bytes)
        {
            krabs::guid wininet(L"{43D1A55C-76D6-4F7E-995C-64C711E5CAFE}");
            krabs::testing::record_builder builder(wininet, 414, 0);
            BYTE bytes[] = { 0xA1, 0x00, 0xB2 };
            builder.add_properties()(L"PayloadByteLength", (uint32_t)sizeof(bytes))
                (L"Payload", krabs::binary(bytes, sizeof(bytes)));
            auto record = builder.pack_incomplete();
            krabs::schema schema(record, schema_locator_);
            krabs::parser parser(schema);
            auto value = parser.parse<krabs::binary>(L"Payload");
            Assert::IsTrue(value.bytes() == std::vector<BYTE>(bytes, bytes + sizeof(bytes)));
        }

        TEST_METHOD(should_remember_added_properties)
        {
            krabs::guid id(krabs::guid::random_guid());
            krabs::testing::record_builder builder(id, krabs::id(1), krabs::version(1));
            builder.add_properties()
                (L"Foo", L"Value")
                (L"Bar", L"Value");

            Assert::AreEqual(builder.properties().size(), static_cast<size_t>(2));
            Assert::AreEqual(builder.properties().at(0).name(), std::wstring(L"Foo"));
            Assert::AreEqual(builder.properties().at(1).name(), std::wstring(L"Bar"));
        }

        TEST_METHOD(pack_should_throw_when_an_incomplete_record_is_built)
        {
            krabs::guid powershell(L"{A0C1853B-5C40-4B15-8766-3CF1C58F985A}");
            krabs::testing::record_builder builder(powershell, krabs::id(7942), krabs::version(1));
            builder.add_properties()
                (L"ClassName", L"FakeETWEventForRealz")
                (L"Message", L"This message is completely faked");

            Assert::ExpectException<std::invalid_argument>([&] {
                builder.pack();
            });
        }

        TEST_METHOD(pack_should_not_throw_when_a_complete_record_is_built)
        {
            krabs::guid powershell(L"{A0C1853B-5C40-4B15-8766-3CF1C58F985A}");
            krabs::testing::record_builder builder(powershell, krabs::id(7942), krabs::version(1));

            builder.add_properties()
                (L"ClassName", L"FakeETWEventForRealz")
                (L"MethodName", L"asdf")
                (L"WorkflowGuid", L"asdfasdfasdf")
                (L"Message", L"This message is completely faked")
                (L"JobData", L"asdfasdf")
                (L"ActivityName", L"asaaa")
                (L"ActivityGuid", L"aaaaa")
                (L"Parameters", L"asfd");

            // call it and see if it throws.
            builder.pack();
        }

        TEST_METHOD(pack_should_throw_when_property_type_mismatched_with_schema)
        {
            krabs::guid powershell(L"{A0C1853B-5C40-4B15-8766-3CF1C58F985A}");
            krabs::testing::record_builder builder(powershell, krabs::id(7942), krabs::version(1));

            builder.add_properties()
                (L"ClassName", 45);

            Assert::ExpectException<std::invalid_argument>([&] {
                builder.pack();
            });
        }

        TEST_METHOD(pack_incomplete_should_not_throw_when_incomplete_record_built)
        {
            krabs::guid powershell(L"{A0C1853B-5C40-4B15-8766-3CF1C58F985A}");
            krabs::testing::record_builder builder(powershell, krabs::id(7942), krabs::version(1));

            builder.add_properties()
                (L"ClassName", L"FakeETWEventForRealz")
                (L"Message", L"This message is completely faked");

            // Call and see if it throws.
            builder.pack_incomplete();
        }

        TEST_METHOD(pack_incomplete_should_fill_enough_bytes_to_enable_reading_props_when_incomplete)
        {
            krabs::guid powershell(L"{A0C1853B-5C40-4B15-8766-3CF1C58F985A}");
            krabs::testing::record_builder builder(powershell, krabs::id(7942), krabs::version(1));

            builder.add_properties()
                (L"ClassName", L"FClassName")
                // Note: skips a few properties to so we can be sure we're padding the buffer
                (L"Message", L"Fake message");

            auto record = builder.pack_incomplete();
            krabs::schema schema(record, schema_locator_);
            krabs::parser parser(schema);

            Assert::AreEqual(parser.parse<std::wstring>(L"ClassName"), std::wstring(L"FClassName"));
            Assert::AreEqual(parser.parse<std::wstring>(L"Message"), std::wstring(L"Fake message"));
        }

        TEST_METHOD(pack_incomplete_should_fill_enough_bytes_for_nonstring_types_when_incomplete)
        {
            krabs::guid wininet(L"{43D1A55C-76D6-4F7E-995C-64C711E5CAFE}");
            krabs::testing::record_builder builder(wininet, krabs::id(1057), krabs::version(0));

            builder.add_properties()
                (L"URL", "https://microsoft.com")
                (L"Status", (unsigned int)300);

            auto record = builder.pack_incomplete();
            krabs::schema schema(record, schema_locator_);
            krabs::parser parser(schema);

            Assert::AreEqual(parser.parse<unsigned int>(L"Status"), (unsigned int)300);
            Assert::AreEqual(parser.parse<std::string>(L"URL"), std::string("https://microsoft.com"));
        }

        TEST_METHOD(pack_incomplete_should_correctly_handle_no_set_props)
        {
            krabs::guid powershell(L"{A0C1853B-5C40-4B15-8766-3CF1C58F985A}");
            krabs::testing::record_builder builder(powershell, krabs::id(7942), krabs::version(1));
            auto record = builder.pack_incomplete();
        }

        TEST_METHOD(pack_incomplete_should_correctly_handle_sid_in_event)
        {
            krabs::guid logon(L"{199FE037-2B82-40A9-82AC-E1D46C792B99}");
            krabs::testing::record_builder builder(logon, krabs::id(301), krabs::version(0));
            builder.add_properties()
                (L"TargetUserName", L"")
                (L"LogonType", (uint32_t)5);

            auto record = builder.pack_incomplete();

            krabs::schema schema(record, schema_locator_);
            krabs::parser parser(schema);
            Assert::AreEqual(parser.parse<uint32_t>(L"LogonType"), (uint32_t)5);
        }

        TEST_METHOD(pack_incomplete_should_correctly_handle_wbemsid_in_event)
        {
            // Classic MOF Process/Start (version 3), leaving the WBEMSID UserSID unset.
            krabs::guid processClass(L"{3D6FA8D0-FE05-11D0-9DDA-00C04FD7BA7C}");
            krabs::testing::record_builder builder(processClass, krabs::id(0), krabs::version(3), krabs::opcode(1));
            builder.header().Flags = EVENT_HEADER_FLAG_CLASSIC_HEADER;
            builder.add_properties()
                (L"ImageFileName", std::string("notepad.exe"));

            auto record = builder.pack_incomplete();

            krabs::schema schema(record, schema_locator_);
            krabs::parser parser(schema);
            Assert::AreEqual(std::string("notepad.exe"), parser.parse<std::string>(L"ImageFileName"));
        }

        TEST_METHOD(pack_should_include_extended_data)
        {
            krabs::guid powershell(L"{A0C1853B-5C40-4B15-8766-3CF1C58F985A}");
            krabs::testing::record_builder builder(powershell, krabs::id(7942), krabs::version(1));
            // Random GUID
            builder.add_container_id_extended_data(krabs::guid(L"{86E2A814-8893-431D-A1DC-F44931D6B99A}"));
            
            // Have to hold onto the record instance so that the data buffers don't get deleted.
            auto synth_record = builder.pack_incomplete();
            const EVENT_RECORD& record = synth_record;

            // USHORT has template specialization issues, so use uint.
            Assert::AreEqual((unsigned int)record.ExtendedDataCount, 1u);
            Assert::IsNotNull(record.ExtendedData);
        }

        TEST_METHOD(pack_should_correctly_handle_no_extended_data)
        {
            krabs::guid powershell(L"{A0C1853B-5C40-4B15-8766-3CF1C58F985A}");
            krabs::testing::record_builder builder(powershell, krabs::id(7942), krabs::version(1));
            
            // Have to hold onto the record instance so that the data buffers don't get deleted.
            auto synth_record = builder.pack_incomplete();
            const EVENT_RECORD& record = synth_record;
            
            // USHORT has template specialization issues, so use uint.
            Assert::AreEqual((unsigned int)record.ExtendedDataCount, 0u);
            Assert::IsNull(record.ExtendedData);
        }

        TEST_METHOD(pack_should_correctly_handle_multiple_extended_data)
        {
            // This assumes that the builder isn't enforcing semantic constraints like "you can't 
            // have more than one container ID extended data item in the same event". Which is
            // probably true for events you'd get from the real API, but we're going to exploit the
            // loophole to test the "multiple extended data" case.
            krabs::guid powershell(L"{A0C1853B-5C40-4B15-8766-3CF1C58F985A}");
            krabs::testing::record_builder builder(powershell, krabs::id(7942), krabs::version(1));
            // Random GUID
            builder.add_container_id_extended_data(krabs::guid(L"{86E2A814-8893-431D-A1DC-F44931D6B99A}"));
            builder.add_container_id_extended_data(krabs::guid(L"{86E2A814-8893-431D-A1DC-F44931D6B99A}"));

            // Have to hold onto the record instance so that the data buffers don't get deleted.
            auto synth_record = builder.pack_incomplete();
            const EVENT_RECORD& record = synth_record;

            // USHORT has template specialization issues, so use uint.
            Assert::AreEqual((unsigned int)record.ExtendedDataCount, 2u);
            Assert::IsNotNull(record.ExtendedData);

            // Sanity check
            Assert::AreEqual((unsigned int)record.ExtendedData[0].ExtType, (unsigned int)EVENT_HEADER_EXT_TYPE_CONTAINER_ID);
            Assert::AreEqual((unsigned int)record.ExtendedData[1].ExtType, (unsigned int)EVENT_HEADER_EXT_TYPE_CONTAINER_ID);
        }

        TEST_METHOD(container_id_should_be_read_correctly_after_packing)
        {
            // Randomly generated GUID
            const krabs::guid CONTAINER_GUID(L"{86E2A814-8893-431D-A1DC-F44931D6B99A}");

            krabs::guid powershell(L"{A0C1853B-5C40-4B15-8766-3CF1C58F985A}");
            krabs::testing::record_builder builder(powershell, krabs::id(7942), krabs::version(1));
            builder.add_container_id_extended_data(CONTAINER_GUID);
            
            // Have to hold onto the record instance so that the data buffers don't get deleted.
            auto synth_record = builder.pack_incomplete();
            const EVENT_RECORD& record = synth_record;

            // USHORT has template specialization issues, so use uint.
            Assert::AreEqual((unsigned int)record.ExtendedDataCount, 1u);
            Assert::IsNotNull(record.ExtendedData);
            
            auto& extended_data = record.ExtendedData[0];
            Assert::AreEqual((unsigned int)extended_data.ExtType, (unsigned int)EVENT_HEADER_EXT_TYPE_CONTAINER_ID);
            Assert::AreEqual((size_t)extended_data.DataSize, krabs::testing::extended_data_builder::GUID_STRING_LENGTH_NO_BRACES);
            
            auto parsed_guid = krabs::guid_parser::parse_guid(
                reinterpret_cast<const char*>(extended_data.DataPtr), 
                extended_data.DataSize);

            // Check that the right GUID came out.
            Assert::IsTrue(CONTAINER_GUID == krabs::guid(parsed_guid));
        }

        TEST_METHOD(pack_should_include_process_start_key_extended_data)
        {
            krabs::guid powershell(L"{A0C1853B-5C40-4B15-8766-3CF1C58F985A}");
            krabs::testing::record_builder builder(powershell, krabs::id(7942), krabs::version(1));
            ULONG64 key = 0x123456789ABCDEF0;
            builder.add_process_start_key_extended_data(key);

            auto synth_record = builder.pack_incomplete();
            const EVENT_RECORD& record = synth_record;

            Assert::AreEqual((unsigned int)record.ExtendedDataCount, 1u);
            Assert::IsNotNull(record.ExtendedData);
            Assert::AreEqual((unsigned int)record.ExtendedData[0].ExtType, (unsigned int)EVENT_HEADER_EXT_TYPE_PROCESS_START_KEY);
        }

        TEST_METHOD(process_start_key_should_be_read_correctly_after_packing)
        {
            const ULONG64 EXPECTED_KEY = 0x123456789ABCDEF0;

            krabs::guid powershell(L"{A0C1853B-5C40-4B15-8766-3CF1C58F985A}");
            krabs::testing::record_builder builder(powershell, krabs::id(7942), krabs::version(1));
            ULONG64 key = EXPECTED_KEY;
            builder.add_process_start_key_extended_data(key);

            auto synth_record = builder.pack_incomplete();
            const EVENT_RECORD& record = synth_record;

            Assert::AreEqual((unsigned int)record.ExtendedDataCount, 1u);
            Assert::IsNotNull(record.ExtendedData);

            auto& extended_data = record.ExtendedData[0];
            Assert::AreEqual((unsigned int)extended_data.ExtType, (unsigned int)EVENT_HEADER_EXT_TYPE_PROCESS_START_KEY);
            Assert::AreEqual((size_t)extended_data.DataSize, sizeof(ULONG64));

            auto parsed_key = *reinterpret_cast<const ULONG64*>(extended_data.DataPtr);
            Assert::AreEqual(EXPECTED_KEY, parsed_key);
        }

        TEST_METHOD(process_start_key_should_be_read_via_schema)
        {
            const ULONG64 EXPECTED_KEY = 0xDEADBEEFCAFEBABE;

            krabs::guid powershell(L"{A0C1853B-5C40-4B15-8766-3CF1C58F985A}");
            krabs::testing::record_builder builder(powershell, krabs::id(7942), krabs::version(1));
            ULONG64 key = EXPECTED_KEY;
            builder.add_process_start_key_extended_data(key);

            auto synth_record = builder.pack_incomplete();
            krabs::schema schema(synth_record, schema_locator_);

            Assert::AreEqual(EXPECTED_KEY, schema.process_start_key());
        }

        TEST_METHOD(process_start_key_should_return_zero_when_not_present)
        {
            krabs::guid powershell(L"{A0C1853B-5C40-4B15-8766-3CF1C58F985A}");
            krabs::testing::record_builder builder(powershell, krabs::id(7942), krabs::version(1));

            auto synth_record = builder.pack_incomplete();
            krabs::schema schema(synth_record, schema_locator_);

            Assert::AreEqual((ULONG64)0, schema.process_start_key());
        }

        private:
            krabs::schema_locator schema_locator_;
    };
}