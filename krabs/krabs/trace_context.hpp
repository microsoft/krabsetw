// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma once

#include "schema_locator.hpp"

namespace krabs {

    /**
     * <summary>
     * Additional ETW trace context passed to event callbacks
     * to enable processing.
     * </summary>
     */
    struct trace_context
    {
        /**
         * NB: not const - krabs::trace configures the locator's per-provider
         * policies when a provider is enabled. Callbacks only ever see this
         * through a const trace_context&.
         */
        schema_locator schema_locator;
        /* Add additional trace context here. */
    };

}
