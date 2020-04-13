// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// This example shows how to use a user_trace to extract powershell command
// invocations. It demonstrates provider-level filtering to make event handling
// code a little simpler.

#include <iostream>
#include <cassert>

#include "..\..\krabs\krabs.hpp"
#include "examples.h"

void user_trace_006_predicate_vectors::start()
{
    krabs::user_trace trace(L"My Named Trace");

    // We will use the Process Trace
    krabs::provider<> provider(L"Microsoft-Windows-Kernel-Process");
    provider.any(0x10);


    krabs::predicates::id_is id_is_1 = krabs::predicates::id_is(1);
    krabs::predicates::id_is id_is_2 = krabs::predicates::id_is(2);
    krabs::predicates::id_is opcode_is_1 = krabs::predicates::id_is(2);
    krabs::predicates::id_is opcode_is_2 = krabs::predicates::id_is(2);
    std::vector<krabs::predicates::details::predicate_base*> vector_ids = {
        &id_is_1,
        &id_is_2,
        &opcode_is_1,
        &opcode_is_2,
    };

    // We'll make one filter of if the ID is 1 OR 2, or OPCODE is 1
    krabs::predicates::or_filter_vector or_pred_ids = krabs::predicates::or_filter_vector(vector_ids);
    krabs::event_filter or_filter(or_pred_ids);
    or_filter.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
        krabs::schema schema(record, trace_context.schema_locator);
        assert(schema.event_id() == 1 || schema.event_id() == 2);
        printf("Event ID: %d || Opcode: %d\n", schema.event_id(), schema.event_opcode());
        });
    provider.add_filter(or_filter);

    // We'll make an AND filter, that should never work (as an ID can't be two numbers ar once
    krabs::predicates::and_filter_vector and_pred_ids = krabs::predicates::and_filter_vector(vector_ids);
    krabs::event_filter and_filter(and_pred_ids);
    and_filter.add_on_event_callback([](const EVENT_RECORD&, const krabs::trace_context&) {
        // This should never be called
        assert(false);
        });
    provider.add_filter(and_filter);

    trace.enable(provider);
    trace.start();
}
