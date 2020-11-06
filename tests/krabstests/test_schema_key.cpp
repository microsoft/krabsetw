// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "CppUnitTest.h"
#include <krabs.hpp>

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace krabstests
{
    TEST_CLASS(test_schema_key)
    {
    public:
        TEST_METHOD(operator_equals)
        {
            const EVENT_RECORD eventRecord = {};
            const krabs::schema_key key1{ eventRecord };
            const krabs::schema_key key2{ eventRecord };

            Assert::IsTrue(key1 == key2);
        }
        TEST_METHOD(hash_specialization)
        {
            const EVENT_RECORD eventRecord = {};
            const krabs::schema_key key1{ eventRecord };
            const krabs::schema_key key2{ eventRecord };

            const std::hash<krabs::schema_key> hash;

            // When a defect is present, this may only fail in Release builds
            // Ref: https://github.com/microsoft/krabsetw/issues/139
            Assert::IsTrue(hash(key1) == hash(key2));
        }
    };
}