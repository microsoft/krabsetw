// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// This example shows how to quickly load up a kernel trace that prints out
// a notice whenever a binary image (executable or DLL) is loaded.

#include <iostream>
#include "..\..\krabs\krabs.hpp"
#include "..\..\krabs\krabs\perfinfo_groupmask.hpp"
#include "examples.h"

void kernel_trace_001::start()
{
    // Kernel traces use the kernel_trace class, which looks and acts a lot like the
    // user_trace class.
    krabs::kernel_trace trace(L"My magic trace");

    // Krabs provides a bunch of convenience providers for kernel traces. The set of
    // providers that are allowed by kernel traces is hardcoded by Windows ETW, and
    // Krabs provides simple objects to represent these. If other providers were
    // enabled without krabs being updated, the same thing could be done like so:
    //    krabs::kernel_provider provider(SOME_ULONG_FLAG_VALUE, SOME_GUID);
    krabs::kernel::image_load_provider provider;

    // Kernel providers accept all the typical callback mechanisms.
    provider.add_on_event_callback([](const EVENT_RECORD &record, const krabs::trace_context &trace_context) {
        krabs::schema schema(record, trace_context.schema_locator);

        // To filter our events, we want to compare against the
        // event opcode. For kernel traces, you can consult this page
        // https://msdn.microsoft.com/en-us/library/windows/desktop/aa364083(v=vs.85).aspx
        //
        // The documentation specific to the image load provider is here:
        // https://msdn.microsoft.com/en-us/library/windows/desktop/aa364068(v=vs.85).aspx
        if (schema.event_opcode() == 10) {
            krabs::parser parser(schema);
            std::wstring filename = parser.parse<std::wstring>(L"FileName");
            std::wcout << L"Loaded image from file " << filename << std::endl;
        }
    });

    // Some kernel providers can't be enabled via EnableFlags and you need to call
    // TraceSetInformation with an extended PERFINFO_GROUPMASK instead.
    // e.g. https://docs.microsoft.com/en-us/windows/win32/etw/obtrace
    // Krabs has convenience providers for some of these, but otherwise the same
    // thing could be done with:
    //    krabs::kernel_provider provider(SOME_GUID, SOME_ULONG_MASK_VALUE);
    krabs::kernel::object_manager_provider ob_provider;
    ob_provider.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
        if (record.EventHeader.EventDescriptor.Opcode == 33) {
            krabs::schema schema(record, trace_context.schema_locator);
            krabs::parser parser(schema);
            std::wstring name = parser.parse<std::wstring>(L"ObjectName");
            std::wcout << L"Handle closed for object with name " << name << std::endl;
        }
    });

    // From here on out, a kernel_trace is indistinguishable from a user_trace in how
    // it is used.
    trace.enable(provider);
    trace.enable(ob_provider);
    trace.start();
}
