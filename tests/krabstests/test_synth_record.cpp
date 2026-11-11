// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "CppUnitTest.h"
#include <krabs.hpp>

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace krabstests
{
    TEST_CLASS(test_synth_record)
    {
    public:

        TEST_METHOD(rejects_payload_length_that_cannot_fit_the_record)
        {
            EVENT_RECORD record = {};
            std::vector<BYTE> data(65536);
            Assert::ExpectException<std::invalid_argument>([&] {
                krabs::testing::synth_record oversized(record, data);
            });
        }

        TEST_METHOD(accepts_the_largest_representable_payload)
        {
            EVENT_RECORD record = {};
            std::vector<BYTE> data(65535, 0xA5);
            krabs::testing::synth_record packed(record, data);
            const EVENT_RECORD& actual = packed;
            Assert::AreEqual((unsigned)65535, (unsigned)actual.UserDataLength);
            Assert::AreEqual((BYTE)0xA5, ((BYTE*)actual.UserData)[65534]);
        }

        TEST_METHOD(should_deep_copy)
        {
            EVENT_RECORD record;
            std::vector<BYTE> data{ 0 };

            krabs::testing::synth_record first(record, data);
            krabs::testing::synth_record second(first);

            auto& first_rec = reinterpret_cast<EVENT_RECORD&>(first);
            auto& second_rec = reinterpret_cast<EVENT_RECORD&>(second);

            Assert::AreNotEqual(second_rec.UserData, first_rec.UserData);
        }

        TEST_METHOD(should_move)
        {
            EVENT_RECORD record;
            std::vector<BYTE> data{ 0 };

            krabs::testing::synth_record first(record, data);

            auto first_data = reinterpret_cast<EVENT_RECORD&>(first).UserData;

            krabs::testing::synth_record second(std::move(first));
            auto& second_rec = (EVENT_RECORD&)second;

            Assert::AreEqual(second_rec.UserData, first_data);
        }
    };
}