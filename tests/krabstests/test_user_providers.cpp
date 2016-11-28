// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "CppUnitTest.h"
#include <krabs.hpp>

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace krabstests
{
    static DWORD WINAPI threadproc(void*)
    {
        krabs::provider<> foo(L"Microsoft-Windows-WinINet");
        return 0;
    }

    TEST_CLASS(test_user_providers)
    {
    public:

        TEST_METHOD(should_be_instantiatable_compilation_test)
        {
            krabs::provider<> foo(krabs::guid::random_guid());
        }

        TEST_METHOD(should_be_instantiatable_by_name)
        {
            // Because of VS's goobiness, we need a new thread
            // to create this type in. VS Test Runner starts the current
            // thread and initializes the STA COM apartment but krabsetw
            // wants to initialize as a MTA COM apartment.
            DWORD thread_id = 0;

             HANDLE my_thread = CreateThread(
                nullptr,
                0,
                reinterpret_cast<LPTHREAD_START_ROUTINE>(threadproc),
                nullptr,
                0,
                &thread_id);

            Assert::IsFalse(my_thread == nullptr);

            // Infinite wait... which should actually be fine
            // since we are literally creating a type and returning.
            WaitForSingleObject(my_thread, INFINITE);

            if (my_thread != nullptr) CloseHandle(my_thread);
        }

        TEST_METHOD(should_allow_event_registration)
        {
            krabs::provider<> foo(krabs::guid::random_guid());
            foo.add_on_event_callback([](const EVENT_RECORD &) {});
        }

        TEST_METHOD(should_allow_any_all_level_flag_settings)
        {
            krabs::provider<> foo(krabs::guid::random_guid());
            foo.any(0x23);
            foo.all(0xFF);
            foo.level(0x0);
        }

        TEST_METHOD(should_be_addable_to_user_trace)
        {
            krabs::user_trace trace;
            krabs::provider<> foo(krabs::guid::random_guid());
            trace.enable(foo);
        }
    };
}