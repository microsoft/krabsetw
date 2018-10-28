// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// This example doing the same as user_trace_002 but using native events filtering (not a predicates)
//

#include <iostream>
#include <cassert>

#include "..\..\krabs\krabs.hpp"
#include "examples.h"

void user_trace_003_no_predicates::start()
{
    // user_trace instances should be used for any non-kernel traces that are defined
    // by components or programs in Windows. They can optionally take a name -- if none
    // is provided, a random GUID is assigned as the name.
    krabs::user_trace trace(L"My Named Trace");

    // A trace can have any number of providers, which are identified by GUID. These
    // GUIDs are defined by the components that emit events, and their GUIDs can
    // usually be found with various ETW tools (like wevutil).

	//listen for file events
    krabs::provider<> provider(krabs::guid(L"{EDD08927-9CC4-4E65-B970-C2560FB5C289}"));

    // In user_trace_001.cpp, we manually filter events by checking the event information
    // in our callback functions. In this example, we're going to use a provider filter
    // to do this for us.

    // We instantiate an event_filter first. An event_filter is created with a
    // predicate -- literally just a function that does some check on an EVENT_RECORD
    // and returns a boolean -- true when the event should be passed on to callbacks,
    // and false otherwise.

    // krabs provides direct native filtering - that will boost performance and not liesten 
	//for event which not required. We'll use one of those to filter based on the event id.

	//listen for file create event
    krabs::event_filter filter(11); //event id used without predicate, will be forwarded to API

    // event_filters can have attached callbacks, just like a regular provider.
    filter.add_on_event_callback([](const EVENT_RECORD &record) {
        krabs::schema schema(record);
        assert(schema.event_id() == 11);
        std::wcout << L"Event 11 received!" << std::endl;
    });

    // event_filters are attached to providers. Events that are attached to a filter will
    // only be called when the filter allows the event through. Any events attached to the
    // provider directly will be called for all events that are fired by the ETW producer.
    provider.add_filter(filter);
    trace.enable(provider);
    trace.start();
}
