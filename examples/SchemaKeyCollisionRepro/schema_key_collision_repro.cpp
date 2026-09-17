// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
//
// Repro for https://github.com/microsoft/krabsetw/issues/193
//
// TraceLogging events are identified by name, not by event id (the id is 0). A provider is
// free to emit the same event name from several call sites with different fields. Those
// variants share every field of schema_key - provider, name, id, version, opcode, level and
// keyword - so they collide in schema_locator's cache. The first schema decoded is then
// reused for every variant, and the field values come out shifted.
//
// This program is self-contained: it registers its own TraceLogging provider, emits both
// variants of one event name, consumes them with krabs, and reports PASS or FAIL. No external
// provider or ETL file is required.
//
// Build (from a Developer Command Prompt). UNICODE is required by krabs itself - without it
// KERNEL_LOGGER_NAME resolves to the ANSI variant and kt.hpp fails to compile:
//
//     cl /std:c++17 /EHsc /DUNICODE /D_UNICODE /I..\..\krabs ^
//        schema_key_collision_repro.cpp advapi32.lib tdh.lib
//
// Run elevated - real-time ETW sessions require Administrator.
//
// Expected output before the fix:
//     variant A -> entryPoint, appId
//     variant B -> entryPoint, appId                <-- wrong, 'PartA_PrivTags' is missing
//                                                       and every value is shifted
//     RESULT: FAIL
//
// Expected output after the fix:
//     variant A -> entryPoint, appId
//     variant B -> PartA_PrivTags, entryPoint, appId
//     RESULT: PASS

#include <atomic>
#include <chrono>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

// krabs.hpp must come before TraceLoggingProvider.h: it pulls in the winsock headers, which
// have to be included ahead of windows.h.
#include "..\..\krabs\krabs.hpp"

#include <TraceLoggingProvider.h>

// {8F4C2E1A-7B3D-4E6F-9A2B-1C5D8E3F7A04}
TRACELOGGING_DEFINE_PROVIDER(
    g_repro_provider,
    "KrabsSchemaKeyCollisionRepro",
    (0x8f4c2e1a, 0x7b3d, 0x4e6f, 0x9a, 0x2b, 0x1c, 0x5d, 0x8e, 0x3f, 0x7a, 0x04));

namespace {

    const krabs::guid kReproProviderGuid(L"{8F4C2E1A-7B3D-4E6F-9A2B-1C5D8E3F7A04}");

    // Both variants are emitted under this single name. That is legal TraceLogging, and is
    // what real providers such as Microsoft.Windows.AppLifeCycle.UI do.
    const std::wstring kSharedEventName = L"SharedEventName";

    // Field lists decoded for each observed instance of the shared event name.
    std::mutex g_mutex;
    std::vector<std::vector<std::wstring>> g_decoded;
    std::atomic<int> g_seen{ 0 };

    std::wstring join(const std::vector<std::wstring>& items)
    {
        std::wstring result;
        for (size_t i = 0; i < items.size(); ++i) {
            if (i > 0) {
                result += L", ";
            }
            result += items[i];
        }
        return result;
    }

    void emit_variant_a()
    {
        // Two fields.
        TraceLoggingWrite(
            g_repro_provider,
            "SharedEventName",
            TraceLoggingUInt32(1005, "entryPoint"),
            TraceLoggingString("MSEdge", "appId"));
    }

    void emit_variant_b()
    {
        // Same event name, but with a leading UInt64 and therefore a different layout.
        TraceLoggingWrite(
            g_repro_provider,
            "SharedEventName",
            TraceLoggingUInt64(50331648, "PartA_PrivTags"),
            TraceLoggingUInt32(23, "entryPoint"),
            TraceLoggingString("MSEdge", "appId"));
    }

} // namespace

int main()
{
    if (TraceLoggingRegister(g_repro_provider) != ERROR_SUCCESS) {
        std::wcerr << L"Failed to register the TraceLogging provider." << std::endl;
        return 2;
    }

    krabs::user_trace trace(L"KrabsSchemaKeyCollisionRepro");
    krabs::provider<> provider(kReproProviderGuid);
    provider.any(0xffffffffffffffff);

    provider.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
        krabs::schema schema(record, trace_context.schema_locator);

        if (std::wstring(schema.event_name()) != kSharedEventName) {
            return;
        }

        // Record the field names krabs decoded for this instance.
        std::vector<std::wstring> fields;
        krabs::parser parser(schema);
        for (const krabs::property& prop : parser.properties()) {
            fields.push_back(prop.name());
        }

        {
            std::lock_guard<std::mutex> guard(g_mutex);
            g_decoded.push_back(std::move(fields));
        }

        g_seen.fetch_add(1);
    });

    trace.enable(provider);

    std::thread worker([&trace]() { trace.start(); });

    // Give the session a moment to come up before emitting.
    std::this_thread::sleep_for(std::chrono::milliseconds(2000));

    // Order matters: variant A is emitted first so its (smaller) schema is the one cached.
    emit_variant_a();
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    emit_variant_b();

    // Wait for both events to arrive, with a timeout so the repro cannot hang.
    for (int i = 0; i < 100 && g_seen.load() < 2; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    trace.stop();
    worker.join();
    TraceLoggingUnregister(g_repro_provider);

    std::lock_guard<std::mutex> guard(g_mutex);

    if (g_decoded.size() < 2) {
        std::wcerr << L"Only received " << g_decoded.size()
                   << L" event(s); expected 2. Are you running elevated?" << std::endl;
        return 2;
    }

    const std::vector<std::wstring>& variantA = g_decoded[0];
    const std::vector<std::wstring>& variantB = g_decoded[1];

    std::wcout << L"variant A -> " << join(variantA) << std::endl;
    std::wcout << L"variant B -> " << join(variantB) << std::endl;
    std::wcout << std::endl;

    // Variant B declares one more field than variant A. If krabs handed back the same field
    // list for both, the cached schema from variant A was reused to decode variant B.
    const bool schemasCollided = (variantA == variantB);

    if (schemasCollided) {
        std::wcout << L"RESULT: FAIL - both variants decoded with the same schema ("
                   << variantA.size() << L" fields)." << std::endl;
        std::wcout << L"The schema cached for the first variant was reused for the second, so"
                   << std::endl;
        std::wcout << L"every field of variant B is shifted. Expected variant B to expose"
                   << std::endl;
        std::wcout << L"'PartA_PrivTags' as its first field." << std::endl;
        return 1;
    }

    const bool variantBCorrect =
        variantB.size() == 3 &&
        variantB[0] == L"PartA_PrivTags" &&
        variantB[1] == L"entryPoint" &&
        variantB[2] == L"appId";

    if (!variantBCorrect) {
        std::wcout << L"RESULT: FAIL - variant B decoded with an unexpected field list."
                   << std::endl;
        return 1;
    }

    std::wcout << L"RESULT: PASS - each variant decoded with its own schema." << std::endl;
    return 0;
}
