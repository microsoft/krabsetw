// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma once

#include <stdexcept>

#include "compiler_check.hpp"

namespace krabs {

    class trace_already_registered : public std::runtime_error {
    public:
        trace_already_registered()
        : std::runtime_error("The trace session has already been registered")
        {}
    };

    class invalid_parameter : public std::logic_error {
    public:
        invalid_parameter()
        : std::logic_error("Invalid parameter given")
        {}
    };

    class start_trace_failure : public std::runtime_error {
    public:
        start_trace_failure()
        : std::runtime_error("Failure to start trace")
        {}
    };

    class need_to_be_admin_failure : public std::runtime_error {
    public:
        need_to_be_admin_failure()
        : std::runtime_error("Need to be an admin")
        {}
    };

    class could_not_find_schema : public std::runtime_error {
    public:
        could_not_find_schema()
        : std::runtime_error("Could not find the schema")
        {}
    };

    class type_mismatch_assert : public std::runtime_error {
    public:
        type_mismatch_assert(
            const char* property,
            const char* actual,
            const char* requested)
            : std::runtime_error(std::string("Attempt to read property '") +
            property + "' type " + actual + " as " + requested)
        {}
    };

    /**
     * <summary>Checks for common ETW API error codes.</summary>
     */
    inline void error_check_common_conditions(ULONG status)
    {
        if (status == ERROR_SUCCESS) {
            return;
        }

        switch (status) {

            case ERROR_ALREADY_EXISTS:
                throw krabs::trace_already_registered();
                break;
            case ERROR_INVALID_PARAMETER:
                throw krabs::invalid_parameter();
                break;
            case ERROR_ACCESS_DENIED:
                throw krabs::need_to_be_admin_failure();
                break;
            case ERROR_NOT_FOUND:
                throw krabs::could_not_find_schema();
                break;
            default:
                throw std::runtime_error("Unexpected error");
        }
    }
}
