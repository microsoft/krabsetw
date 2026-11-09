// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "CppUnitTest.h"
#include <krabs.hpp>

#include <sddl.h>

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace krabstests
{
    TEST_CLASS(test_parse_types)
    {
    private:

        /**
         * Builds a SID: revision, sub-authority count, a 6-byte big-endian
         * identifier authority, then the sub-authorities. The count byte is the
         * real count truncated to a byte, so over-long SIDs can be built for the
         * invalid cases.
         */
        static std::vector<BYTE> MakeSid(BYTE revision, uint64_t authority, const std::vector<DWORD>& subAuthorities)
        {
            std::vector<BYTE> bytes(8 + subAuthorities.size() * sizeof(DWORD));
            bytes[0] = revision;
            bytes[1] = static_cast<BYTE>(subAuthorities.size());
            for (int i = 0; i < 6; ++i) {
                bytes[2 + i] = static_cast<BYTE>(authority >> (8 * (5 - i)));
            }
            if (!subAuthorities.empty()) {
                memcpy(&bytes[8], subAuthorities.data(), subAuthorities.size() * sizeof(DWORD));
            }
            return bytes;
        }

        /**
         * Formats a SID with ConvertSidToStringSidA, the reference that
         * krabs::sid::from_bytes must match.
         */
        static std::string ApiSidString(const std::vector<BYTE>& sid)
        {
            LPSTR text = nullptr;
            Assert::IsTrue(ConvertSidToStringSidA((PSID)sid.data(), &text) != FALSE);
            std::string result(text);
            LocalFree(text);
            return result;
        }

    public:
        TEST_METHOD(counted_string)
        {
            // the counted string is len 5 (10 bytes), pack(1) and doesn't include ! chars
            const wchar_t* counted_string_data = L"\x0A" L"ABCDE!!!!!";
            auto cs = reinterpret_cast<const krabs::counted_string*>(counted_string_data);

            Assert::IsTrue(cs->size_ == 0x0A);
            Assert::IsTrue(cs->string_[0] == 'A');
        }

        TEST_METHOD(sid_from_bytes_should_match_ConvertSidToStringSid)
        {
            std::vector<std::vector<BYTE>> sids;

            // Well-known and typical SIDs.
            for (const char* text : {
                    "S-1-0-0", "S-1-1-0", "S-1-5-18", "S-1-5-32-544", "S-1-16-12288",
                    "S-1-5-21-3623811015-3361044348-30300820-1013",
                    "S-1-15-2-1430448594-2639229838-973813799-439329657-1197984847-4069167804-1277922394" }) {
                PSID psid = nullptr;
                Assert::IsTrue(ConvertStringSidToSidA(text, &psid) != FALSE);
                const BYTE* bytes = reinterpret_cast<const BYTE*>(psid);
                sids.emplace_back(bytes, bytes + GetLengthSid(psid));
                LocalFree(psid);
            }

            // No sub-authorities, and the maximum of 15.
            sids.push_back(MakeSid(1, 5, {}));
            sids.push_back(MakeSid(1, 5, std::vector<DWORD>(SID_MAX_SUB_AUTHORITIES, 0xFFFFFFFF)));

            // Every boundary where the number of decimal digits changes.
            sids.push_back(MakeSid(1, 9, { 0, 9, 10, 99, 100, 999, 1000, 99999, 100000 }));
            sids.push_back(MakeSid(1, 10, { 9999999, 10000000, 99999999, 100000000, 999999999, 1000000000, 0xFFFFFFFF }));

            for (const auto& sid : sids) {
                Assert::AreEqual(ApiSidString(sid), krabs::sid::from_bytes(sid.data(), sid.size()).sid_string);
            }
        }

        TEST_METHOD(sid_from_bytes_should_write_authorities_above_32_bits_as_unpadded_uppercase_hex)
        {
            // ConvertSidToStringSid writes an identifier authority in decimal while
            // it fits in 32 bits, and as 0x-prefixed uppercase hex without leading
            // zeros above that -- not as the 12 hex digits its 6-byte field suggests.
            const std::pair<uint64_t, const char*> cases[] = {
                { 0x00000000FFFFFFFFull, "S-1-4294967295-7" },
                { 0x0000000100000000ull, "S-1-0x100000000-7" },
                { 0x0000000A00000000ull, "S-1-0xA00000000-7" },
                { 0x000000ABCDEF0123ull, "S-1-0xABCDEF0123-7" },
                { 0x0000FFFF00000000ull, "S-1-0xFFFF00000000-7" },
                { 0x0000FFFFFFFFFFFFull, "S-1-0xFFFFFFFFFFFF-7" },
            };

            for (const auto& [authority, expected] : cases) {
                auto sid = MakeSid(1, authority, { 7 });
                // Pin the format, and check Windows still agrees with it.
                Assert::AreEqual(std::string(expected), ApiSidString(sid));
                Assert::AreEqual(std::string(expected), krabs::sid::from_bytes(sid.data(), sid.size()).sid_string);
            }
        }

        TEST_METHOD(sid_from_bytes_should_format_the_longest_possible_sid)
        {
            // Largest authority and 15 maximal sub-authorities: the longest string a
            // valid SID can produce, which must fit from_bytes' fixed-size buffer.
            auto sid = MakeSid(1, 0xFFFFFFFFFFFFull, std::vector<DWORD>(SID_MAX_SUB_AUTHORITIES, 0xFFFFFFFF));
            const auto result = krabs::sid::from_bytes(sid.data(), sid.size()).sid_string;

            Assert::AreEqual(ApiSidString(sid), result);
            Assert::AreEqual(size_t(18 + 15 * 11), result.size()); // "S-1-0xFFFFFFFFFFFF" + 15 * "-4294967295"
        }

        TEST_METHOD(sid_from_bytes_should_ignore_bytes_after_the_sid)
        {
            // A property may be longer than the SID it holds.
            auto sid = MakeSid(1, 5, { 21, 1000 });
            const auto expected = ApiSidString(sid);
            sid.insert(sid.end(), { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF });

            Assert::AreEqual(expected, krabs::sid::from_bytes(sid.data(), sid.size()).sid_string);
        }

        TEST_METHOD(sid_from_bytes_should_read_a_sid_at_an_unaligned_address)
        {
            // SIDs in an event payload are not necessarily 4-byte aligned.
            const auto sid = MakeSid(1, 5, { 21, 3623811015, 3361044348, 30300820, 1013 });
            std::vector<BYTE> buffer(sid.size() + 1);
            std::copy(sid.begin(), sid.end(), buffer.begin() + 1);

            Assert::AreEqual(ApiSidString(sid), krabs::sid::from_bytes(buffer.data() + 1, sid.size()).sid_string);
        }

        TEST_METHOD(sid_from_bytes_should_throw_for_invalid_sids)
        {
            // Rejected by ConvertSidToStringSid too: unknown revisions, and more
            // sub-authorities than a SID can hold.
            for (BYTE revision : { BYTE(0), BYTE(2), BYTE(255) }) {
                auto sid = MakeSid(revision, 5, { 18 });
                Assert::ExpectException<std::runtime_error>([&]() { krabs::sid::from_bytes(sid.data(), sid.size()); });
            }
            for (size_t count : { size_t(SID_MAX_SUB_AUTHORITIES + 1), size_t(255) }) {
                auto sid = MakeSid(1, 5, std::vector<DWORD>(count, 1));
                Assert::ExpectException<std::runtime_error>([&]() { krabs::sid::from_bytes(sid.data(), sid.size()); });
            }

            Assert::ExpectException<std::runtime_error>([&]() { krabs::sid::from_bytes(nullptr, 0); });

            auto header = MakeSid(1, 5, {});
            Assert::ExpectException<std::runtime_error>([&]() { krabs::sid::from_bytes(header.data(), header.size() - 1); });
        }

        TEST_METHOD(sid_from_bytes_should_throw_when_property_is_shorter_than_its_sub_authority_count)
        {
            // The SID claims two sub-authorities but the property only holds one
            // and a half. Never read past the end of the property.
            auto truncated = MakeSid(1, 5, { 21, 1000 });
            truncated.resize(truncated.size() - 2);
            Assert::ExpectException<std::runtime_error>([&]() { krabs::sid::from_bytes(truncated.data(), truncated.size()); });
        }
    };
}
