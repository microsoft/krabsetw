// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "CppUnitTest.h"
#include <krabs.hpp>

#include <string>
#include <vector>

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace krabstests
{
    TEST_CLASS(test_trace_logger_event_name)
    {
    private:

        /**
         * Builds a TraceLogging 'EventMetadata' pseudo-structure:
         *   UINT16 Size;
         *   UINT8  Extension[];  // 1+ bytes, terminated by a byte with the high bit unset
         *   char   Name[];       // UTF-8 nul-terminated
         *   FieldMetadata Fields[];
         */
        static std::vector<char> BuildMetadata(
            const std::vector<unsigned char>& extension,
            const std::string& name,
            bool nulTerminateName = true,
            const std::vector<char>& fields = {})
        {
            std::vector<char> metadata(sizeof(USHORT), 0);

            for (auto b : extension) {
                metadata.push_back(static_cast<char>(b));
            }

            metadata.insert(metadata.end(), name.begin(), name.end());
            if (nulTerminateName) {
                metadata.push_back('\0');
            }

            metadata.insert(metadata.end(), fields.begin(), fields.end());

            *reinterpret_cast<USHORT*>(metadata.data()) = static_cast<USHORT>(metadata.size());
            return metadata;
        }

        static void SetSizeField(std::vector<char>& metadata, USHORT size)
        {
            *reinterpret_cast<USHORT*>(metadata.data()) = size;
        }

        static EVENT_RECORD MakeRecord(
            EVENT_HEADER_EXTENDED_DATA_ITEM& item,
            const std::vector<char>& metadata,
            USHORT extType = EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL,
            USHORT dataSize = 0)
        {
            item = {};
            item.ExtType = extType;
            item.DataPtr = reinterpret_cast<ULONGLONG>(metadata.data());
            item.DataSize = dataSize == 0 ? static_cast<USHORT>(metadata.size()) : dataSize;

            EVENT_RECORD record = {};
            record.ExtendedDataCount = 1;
            record.ExtendedData = &item;
            return record;
        }

    public:

        TEST_METHOD(should_return_empty_when_no_extended_data)
        {
            const EVENT_RECORD record = {};

            Assert::IsTrue(krabs::get_trace_logger_event_name(record).empty());
        }

        TEST_METHOD(should_return_empty_when_extended_data_is_not_trace_logging)
        {
            auto metadata = BuildMetadata({ 0x00 }, "MyEvent");

            EVENT_HEADER_EXTENDED_DATA_ITEM item;
            auto record = MakeRecord(item, metadata, EVENT_HEADER_EXT_TYPE_RELATED_ACTIVITYID);

            Assert::IsTrue(krabs::get_trace_logger_event_name(record).empty());
        }

        TEST_METHOD(should_return_name_for_well_formed_metadata)
        {
            auto metadata = BuildMetadata({ 0x00 }, "MyEvent");

            EVENT_HEADER_EXTENDED_DATA_ITEM item;
            auto record = MakeRecord(item, metadata);

            Assert::AreEqual(std::string("MyEvent"),
                             std::string(krabs::get_trace_logger_event_name(record)));
        }

        TEST_METHOD(should_return_name_when_extension_is_multiple_bytes)
        {
            // Extension bytes chain while the high bit is set.
            auto metadata = BuildMetadata({ 0x81, 0x82, 0x83, 0x04 }, "TaggedEvent");

            EVENT_HEADER_EXTENDED_DATA_ITEM item;
            auto record = MakeRecord(item, metadata);

            Assert::AreEqual(std::string("TaggedEvent"),
                             std::string(krabs::get_trace_logger_event_name(record)));
        }

        TEST_METHOD(should_return_name_when_fields_follow_the_name)
        {
            // A single field named "Count" of some InType - the name must stop
            // at its own nul terminator and not run into the field metadata.
            const std::vector<char> fields{ 'C', 'o', 'u', 'n', 't', '\0', 0x07 };
            auto metadata = BuildMetadata({ 0x00 }, "MyEvent", true, fields);

            EVENT_HEADER_EXTENDED_DATA_ITEM item;
            auto record = MakeRecord(item, metadata);

            Assert::AreEqual(std::string("MyEvent"),
                             std::string(krabs::get_trace_logger_event_name(record)));
        }

        TEST_METHOD(should_return_distinct_names_for_distinct_events)
        {
            // This is the core of https://github.com/microsoft/krabsetw/issues/193 -
            // TraceLogging events share an event id, so the name has to disambiguate.
            auto metadataA = BuildMetadata({ 0x00 }, "EventA");
            auto metadataB = BuildMetadata({ 0x00 }, "EventB");

            EVENT_HEADER_EXTENDED_DATA_ITEM itemA;
            EVENT_HEADER_EXTENDED_DATA_ITEM itemB;
            auto recordA = MakeRecord(itemA, metadataA);
            auto recordB = MakeRecord(itemB, metadataB);

            const krabs::schema_key keyA{ recordA, krabs::get_trace_logger_event_name(recordA) };
            const krabs::schema_key keyB{ recordB, krabs::get_trace_logger_event_name(recordB) };

            Assert::IsTrue(keyA != keyB);
        }

        TEST_METHOD(should_return_name_when_data_item_is_larger_than_metadata)
        {
            // The 'Size' field describes the metadata; the extended data item is
            // allowed to be larger. The name must still be found.
            auto metadata = BuildMetadata({ 0x00 }, "MyEvent");
            const auto structSize = static_cast<USHORT>(metadata.size());
            metadata.insert(metadata.end(), 8, '\0'); // trailing slack
            SetSizeField(metadata, structSize);

            EVENT_HEADER_EXTENDED_DATA_ITEM item;
            auto record = MakeRecord(item, metadata);

            Assert::AreEqual(std::string("MyEvent"),
                             std::string(krabs::get_trace_logger_event_name(record)));
        }

        TEST_METHOD(should_return_empty_when_size_exceeds_data_item)
        {
            auto metadata = BuildMetadata({ 0x00 }, "MyEvent");
            SetSizeField(metadata, static_cast<USHORT>(metadata.size() + 16));

            EVENT_HEADER_EXTENDED_DATA_ITEM item;
            auto record = MakeRecord(item, metadata);

            Assert::IsTrue(krabs::get_trace_logger_event_name(record).empty());
        }

        TEST_METHOD(should_return_empty_when_name_is_not_nul_terminated)
        {
            auto metadata = BuildMetadata({ 0x00 }, "MyEvent", false);

            EVENT_HEADER_EXTENDED_DATA_ITEM item;
            auto record = MakeRecord(item, metadata);

            Assert::IsTrue(krabs::get_trace_logger_event_name(record).empty());
        }

        TEST_METHOD(should_return_empty_when_metadata_is_too_small)
        {
            std::vector<char> metadata{ 0x01 };

            EVENT_HEADER_EXTENDED_DATA_ITEM item;
            auto record = MakeRecord(item, metadata);

            Assert::IsTrue(krabs::get_trace_logger_event_name(record).empty());
        }

        TEST_METHOD(should_return_empty_when_metadata_has_no_name)
        {
            // Extension bytes run to the end of the metadata - no name follows.
            auto metadata = BuildMetadata({ 0x81, 0x82 }, "");
            metadata.pop_back(); // drop the nul so only the extension remains
            SetSizeField(metadata, static_cast<USHORT>(metadata.size()));

            EVENT_HEADER_EXTENDED_DATA_ITEM item;
            auto record = MakeRecord(item, metadata);

            Assert::IsTrue(krabs::get_trace_logger_event_name(record).empty());
        }

        TEST_METHOD(should_return_empty_when_name_is_empty)
        {
            auto metadata = BuildMetadata({ 0x00 }, "");

            EVENT_HEADER_EXTENDED_DATA_ITEM item;
            auto record = MakeRecord(item, metadata);

            Assert::IsTrue(krabs::get_trace_logger_event_name(record).empty());
        }

        TEST_METHOD(should_expose_metadata_bytes_alongside_name)
        {
            auto metadata = BuildMetadata({ 0x00 }, "MyEvent");

            EVENT_HEADER_EXTENDED_DATA_ITEM item;
            auto record = MakeRecord(item, metadata);

            const auto result = krabs::get_trace_logger_event_metadata(record);

            Assert::AreEqual(std::string("MyEvent"), std::string(result.name));
            Assert::IsNotNull(result.data);
            Assert::AreEqual(static_cast<size_t>(result.size), metadata.size());
        }

        TEST_METHOD(should_hash_to_zero_when_there_is_no_metadata)
        {
            // Manifest-based events carry no TraceLogging metadata - they are
            // already identified uniquely by provider/id/version.
            Assert::AreEqual(0ull, krabs::hash_trace_logging_metadata(nullptr, 0));

            const char data[] = "unused";
            Assert::AreEqual(0ull, krabs::hash_trace_logging_metadata(data, 0));
        }

        TEST_METHOD(should_hash_to_nonzero_for_real_metadata)
        {
            // 0 is reserved to mean "no metadata", so real metadata must never
            // hash to it.
            auto metadata = BuildMetadata({ 0x00 }, "MyEvent");

            Assert::AreNotEqual(0ull,
                krabs::hash_trace_logging_metadata(
                    metadata.data(), static_cast<uint16_t>(metadata.size())));
        }

        TEST_METHOD(should_hash_same_for_identical_metadata)
        {
            auto metadataA = BuildMetadata({ 0x00 }, "MyEvent", true, { 'A', '\0', 0x07 });
            auto metadataB = BuildMetadata({ 0x00 }, "MyEvent", true, { 'A', '\0', 0x07 });

            Assert::AreEqual(
                krabs::hash_trace_logging_metadata(
                    metadataA.data(), static_cast<uint16_t>(metadataA.size())),
                krabs::hash_trace_logging_metadata(
                    metadataB.data(), static_cast<uint16_t>(metadataB.size())));
        }

        TEST_METHOD(should_not_share_a_key_when_one_name_declares_different_fields)
        {
            // The heart of https://github.com/microsoft/krabsetw/issues/193.
            // A provider may log the same event name from several call sites with
            // different fields. Everything the old key looked at - provider, id,
            // version, opcode, level, keyword and even the name - is identical, so
            // the two events collided and the first schema decoded both.
            const std::vector<char> fieldsA{ 'C', 'o', 'u', 'n', 't', '\0', 0x07 };
            const std::vector<char> fieldsB{ 'P', 'a', 't', 'h', '\0', 0x02 };

            auto metadataA = BuildMetadata({ 0x00 }, "MyEvent", true, fieldsA);
            auto metadataB = BuildMetadata({ 0x00 }, "MyEvent", true, fieldsB);

            EVENT_HEADER_EXTENDED_DATA_ITEM itemA;
            EVENT_HEADER_EXTENDED_DATA_ITEM itemB;
            auto recordA = MakeRecord(itemA, metadataA);
            auto recordB = MakeRecord(itemB, metadataB);

            const auto metaA = krabs::get_trace_logger_event_metadata(recordA);
            const auto metaB = krabs::get_trace_logger_event_metadata(recordB);

            // Same name ...
            Assert::AreEqual(std::string(metaA.name), std::string(metaB.name));

            // ... but they must not share a cache entry.
            const krabs::schema_key keyA{
                recordA, metaA.name, krabs::hash_trace_logging_metadata(metaA.data, metaA.size) };
            const krabs::schema_key keyB{
                recordB, metaB.name, krabs::hash_trace_logging_metadata(metaB.data, metaB.size) };

            Assert::IsTrue(keyA != keyB);
        }

        TEST_METHOD(should_share_a_key_for_repeats_of_the_same_event)
        {
            // The flip side: identical events must still hit the cache, otherwise
            // the schema lookup is no longer cached at all.
            const std::vector<char> fields{ 'C', 'o', 'u', 'n', 't', '\0', 0x07 };

            auto metadataA = BuildMetadata({ 0x00 }, "MyEvent", true, fields);
            auto metadataB = BuildMetadata({ 0x00 }, "MyEvent", true, fields);

            EVENT_HEADER_EXTENDED_DATA_ITEM itemA;
            EVENT_HEADER_EXTENDED_DATA_ITEM itemB;
            auto recordA = MakeRecord(itemA, metadataA);
            auto recordB = MakeRecord(itemB, metadataB);

            const auto metaA = krabs::get_trace_logger_event_metadata(recordA);
            const auto metaB = krabs::get_trace_logger_event_metadata(recordB);

            const krabs::schema_key keyA{
                recordA, metaA.name, krabs::hash_trace_logging_metadata(metaA.data, metaA.size) };
            const krabs::schema_key keyB{
                recordB, metaB.name, krabs::hash_trace_logging_metadata(metaB.data, metaB.size) };

            Assert::IsTrue(keyA == keyB);
            Assert::IsTrue(std::hash<krabs::schema_key>()(keyA) ==
                           std::hash<krabs::schema_key>()(keyB));
        }
    };
}
