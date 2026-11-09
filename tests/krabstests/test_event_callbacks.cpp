// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "CppUnitTest.h"
#include <krabs.hpp>
#include <chrono>
#include <future>

using namespace Microsoft::VisualStudio::CppUnitTestFramework;
using namespace std::placeholders;


// The tests in this file are designed to verify that the different types
// of callbacks that providers accept (1) compile appropriately and (2)
// are invoked in the appropriate situations. The nature of these tests
// is super gnarly because of the nature of callbacks. Sorry.

bool was_c_style_callback_invoked = false;

void c_style_callback(const EVENT_RECORD &, const krabs::trace_context &)
{
    was_c_style_callback_invoked = true;
}


struct functor {
public:
    void operator()(const EVENT_RECORD &, const krabs::trace_context &)
    {
        called_ = true;
    }

    void my_member_func(const EVENT_RECORD &, const krabs::trace_context &)
    {
        called_ = true;
    }

public:

    bool has_been_called()
    {
        return called_;
    }

private:
    bool called_ = false;
};


// Designed to be used as a temporary, it takes the location of a bool
// that it will populate when it's called.
struct tmp_functor {
public:
    tmp_functor(bool &b)
        : called_(b)
    {}

    void operator()(const EVENT_RECORD &, const krabs::trace_context &)
    {
        called_ = true;
    }

private:
    tmp_functor &operator=(const tmp_functor &) = delete;
    bool &called_;
};


namespace krabstests
{
    TEST_CLASS(test_event_callbacks)
    {
        static krabs::provider<> init()
        {
            // Microsoft-Windows-PowerShell provider
            krabs::guid id(L"{A0C1853B-5C40-4B15-8766-3CF1C58F985A}");
            krabs::provider<> provider(id);
            return provider;
        }

        krabs::provider<> provider = init();
    public:
        TEST_METHOD(real_native_callback_rethrows_after_stopping_the_session)
        {
            const auto id = krabs::guid::random_guid();
            const GUID native_id = id;
            struct registration {
                REGHANDLE handle = 0;
                ~registration() { if (handle != 0) EventUnregister(handle); }
            } source;
            Assert::AreEqual<ULONG>(ERROR_SUCCESS, EventRegister(&native_id, nullptr, nullptr, &source.handle));
            krabs::user_trace trace;
            krabs::provider<> live_provider(id);
            live_provider.add_on_event_callback([](const EVENT_RECORD&, const krabs::trace_context&) {
                throw std::runtime_error("native callback");
            });
            trace.enable(live_provider);
            trace.open();
            auto processing = std::async(std::launch::async, [&] {
                try {
                    trace.start();
                    return std::string();
                }
                catch (const std::exception& error) {
                    return std::string(error.what());
                }
            });
            for (int i = 0; i < 50 && processing.wait_for(std::chrono::milliseconds(0)) !=
                std::future_status::ready; ++i) {
                EventWriteString(source.handle, 0, 0, L"trigger");
                Sleep(100);
            }
            const bool completed = processing.wait_for(std::chrono::seconds(5)) == std::future_status::ready;
            const bool stopped = trace.query_stats().buffersCount == 0;
            trace.stop();
            auto error = processing.get();
            Assert::IsTrue(completed, L"Callback failure did not stop processing");
            Assert::AreEqual(std::string("native callback"), error);
            Assert::IsTrue(stopped, L"Failed processing left the session enabled");
        }

        TEST_METHOD(etw_callback_boundary_contains_native_failures)
        {
            krabs::user_trace trace;
            size_t calls = 0;
            provider.add_on_event_callback([&](const EVENT_RECORD&, const krabs::trace_context&) {
                ++calls;
                throw std::runtime_error("native callback");
            });
            trace.enable(provider);
            EVENT_RECORD record = {};
            record.EventHeader.ProviderId = krabs::guid(L"{A0C1853B-5C40-4B15-8766-3CF1C58F985A}");
            record.UserContext = &trace;
            try {
                krabs::details::trace_callback_thunk<krabs::user_trace>(&record);
                krabs::details::trace_callback_thunk<krabs::user_trace>(&record);
            }
            catch (...) {
                Assert::Fail(L"An exception unwound through the ETW callback boundary");
            }
            Assert::AreEqual<size_t>(1, calls);
            EVENT_TRACE_LOGFILE logfile = {};
            logfile.Context = &trace;
            Assert::AreEqual<ULONG>(FALSE,
                krabs::details::trace_buffer_callback<krabs::user_trace>(&logfile));
        }

        TEST_METHOD(add_callback_should_allow_c_style_functors_as_callback)
        {
            provider.add_on_event_callback(c_style_callback);
        }

        TEST_METHOD(add_callback_should_allow_cpp_style_functors_as_callback)
        {
            functor func;
            provider.add_on_event_callback(func);
        }

        TEST_METHOD(add_callback_should_allow_lambdas_as_callbacks)
        {
            provider.add_on_event_callback([&](const EVENT_RECORD &, const krabs::trace_context &) {});
        }

        TEST_METHOD(add_callback_should_allow_temporary_objects_as_callbacks)
        {
            provider.add_on_event_callback(functor());
        }

        TEST_METHOD(add_callback_should_allow_pointer_to_member_functions_as_callbacks)
        {
            functor func;
            provider.add_on_event_callback(std::bind(&functor::my_member_func, &func, _1, _2));
        }

        TEST_METHOD(trace_add_callback)
        {
            // Set up a user_trace and a provider with several types of callback, verify
            // that the callbacks are invoked.
            krabs::user_trace trace;

            bool was_lambda_invoked = false;
            bool was_tmp_invoked = false;

            functor func1, func2;
            krabs::guid id(L"{A0C1853B-5C40-4B15-8766-3CF1C58F985A}");

            provider.add_on_event_callback(c_style_callback);
            provider.add_on_event_callback(func1);
            provider.add_on_event_callback([&](const EVENT_RECORD &, const krabs::trace_context &) {
                was_lambda_invoked = true;
            });

            provider.add_on_event_callback(tmp_functor(was_tmp_invoked));
            provider.add_on_event_callback(std::bind(&functor::my_member_func, &func2, _1, _2));
            trace.enable(provider);

            // Kick off a fake event.
            krabs::testing::user_trace_proxy proxy(trace);
            proxy.start();

            krabs::testing::record_builder builder(id, krabs::id(7942), krabs::version(1));

            builder.add_properties()
                (L"ClassName", L"FakeETWEventForRealz")
                (L"Message", L"This message is completely faked");

            auto record = builder.pack_incomplete();
            proxy.push_event(record);

            // "should call the C-style callback"
            Assert::IsTrue(was_c_style_callback_invoked);
            
            // "should call the C++-style functor callback"
            Assert::IsTrue(func1.has_been_called());

            // "should call the lambda callback"
            Assert::IsTrue(was_lambda_invoked);

            // "should call the temporary object callback"
            Assert::IsTrue(was_tmp_invoked);

            // "should call the pointer-to-member callback"
            Assert::IsTrue(func2.has_been_called());
        }
    };
}