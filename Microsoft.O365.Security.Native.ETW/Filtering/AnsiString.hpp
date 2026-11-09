// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma once

#include <krabs.hpp>

#include <string>

#include "../NativePtr.hpp"
#include "Predicate.hpp"
#include "../StringEncoding.hpp"
#include <msclr\marshal.h>
#include <msclr\marshal_cppstd.h>

using namespace System;
using namespace System::Runtime::InteropServices;
namespace adapt = krabs::predicates::adapters;

namespace Microsoft { namespace O365 { namespace Security { namespace ETW {

    namespace details {
        template <typename Comparer>
        inline krabs::filter_predicate encoded_string_predicate(
            const std::wstring& name, const std::wstring& value)
        {
            using adapter = adapt::generic_string<char>;
            using predicate = krabs::predicates::details::property_view_predicate<
                std::string, adapter, Comparer>;
            predicate ansi(name, encode_string(value, CP_ACP), adapter(), Comparer());
            predicate utf8(name, encode_string(value, CP_UTF8), adapter(), Comparer());
            return [name, ansi, utf8](const EVENT_RECORD& record, const krabs::trace_context& context) {
                auto info = context.schema_locator.get_event_schema(record);
                return string_code_page(info, name) == CP_UTF8 ?
                    utf8(record, context) : ansi(record, context);
            };
        }
    }

    /// <summary>
    /// Fluent filters for ANSI String properties
    /// </summary>
    public ref class AnsiString abstract sealed {
    public:
        /// <summary>
        /// Accept event if ANSI string property equals the specified string
        /// </summary>
        /// <param name="name">represents the property name</param>
        /// <param name="value">represents the value to match on</param>
        /// <returns>a predicate that accepts an event if the value matches the specified string</returns>
        static Predicate^ Is(String^ name, String^ value)
        {
            return gcnew Predicate(details::encoded_string_predicate<krabs::predicates::comparers::equals<std::equal_to<char>>>(
                msclr::interop::marshal_as<std::wstring>(name),
                msclr::interop::marshal_as<std::wstring>(value)));
        }

        /// <summary>
        /// Accept event if ANSI string property equals (case invariant) the specified string
        /// </summary>
        /// <param name="name">represents the property name</param>
        /// <param name="value">represents the value to match on</param>
        /// <returns>a predicate that accepts an event if the value matches (case invariant) the specified string</returns>
        static Predicate^ IEquals(String^ name, String^ value)
        {
            return gcnew Predicate(details::encoded_string_predicate<krabs::predicates::comparers::equals<krabs::predicates::comparers::iequal_to<char>>>(
                msclr::interop::marshal_as<std::wstring>(name),
                msclr::interop::marshal_as<std::wstring>(value)));
        }

        /// <summary>
        /// Accept event if ANSI string property contains the specified string
        /// </summary>
        /// <param name="name">represents the property name</param>
        /// <param name="value">represents the value to match on</param>
        /// <returns>a predicate that accepts an event if the value contains the specified string</returns>
        static Predicate^ Contains(String^ name, String^ value)
        {
            return gcnew Predicate(details::encoded_string_predicate<krabs::predicates::comparers::contains<std::equal_to<char>>>(
                msclr::interop::marshal_as<std::wstring>(name),
                msclr::interop::marshal_as<std::wstring>(value)));
        }

        /// <summary>
        /// Accept event if ANSI string property contains (case invariant) the specified string
        /// </summary>
        /// <param name="name">represents the property name</param>
        /// <param name="value">represents the value to match on</param>
        /// <returns>a predicate that accepts an event if the value contains (case invariant) the specified string</returns>
        static Predicate^ IContains(String^ name, String^ value)
        {
            return gcnew Predicate(details::encoded_string_predicate<krabs::predicates::comparers::contains<krabs::predicates::comparers::iequal_to<char>>>(
                msclr::interop::marshal_as<std::wstring>(name),
                msclr::interop::marshal_as<std::wstring>(value)));
        }

        /// <summary>
        /// Accept event if ANSI string property starts with the specified string
        /// </summary>
        /// <param name="name">represents the property name</param>
        /// <param name="value">represents the value to match on</param>
        /// <returns>a predicate that accepts an event if the value starts with the specified string</returns>
        static Predicate^ StartsWith(String^ name, String^ value)
        {
            return gcnew Predicate(details::encoded_string_predicate<krabs::predicates::comparers::starts_with<std::equal_to<char>>>(
                msclr::interop::marshal_as<std::wstring>(name),
                msclr::interop::marshal_as<std::wstring>(value)));
        }

        /// <summary>
        /// Accept event if ANSI string property starts with (case invariant) the specified string
        /// </summary>
        /// <param name="name">represents the property name</param>
        /// <param name="value">represents the value to match on</param>
        /// <returns>a predicate that accepts an event if the value starts with (case invariant) the specified string</returns>
        static Predicate^ IStartsWith(String^ name, String^ value)
        {
            return gcnew Predicate(details::encoded_string_predicate<krabs::predicates::comparers::starts_with<krabs::predicates::comparers::iequal_to<char>>>(
                msclr::interop::marshal_as<std::wstring>(name),
                msclr::interop::marshal_as<std::wstring>(value)));
        }

        /// <summary>
        /// Accept event if ANSI string property ends with the specified string
        /// </summary>
        /// <param name="name">represents the property name</param>
        /// <param name="value">represents the value to match on</param>
        /// <returns>a predicate that accepts an event if the value ends with the specified string</returns>
        static Predicate^ EndsWith(String^ name, String^ value)
        {
            return gcnew Predicate(details::encoded_string_predicate<krabs::predicates::comparers::ends_with<std::equal_to<char>>>(
                msclr::interop::marshal_as<std::wstring>(name),
                msclr::interop::marshal_as<std::wstring>(value)));
        }

        /// <summary>
        /// Accept event if ANSI string property ends with (case invariant) the specified string
        /// </summary>
        /// <param name="name">represents the property name</param>
        /// <param name="value">represents the value to match on</param>
        /// <returns>a predicate that accepts an event if the value ends with (case invariant) the specified string</returns>
        static Predicate^ IEndsWith(String^ name, String^ value)
        {
            return gcnew Predicate(details::encoded_string_predicate<krabs::predicates::comparers::ends_with<krabs::predicates::comparers::iequal_to<char>>>(
                msclr::interop::marshal_as<std::wstring>(name),
                msclr::interop::marshal_as<std::wstring>(value)));
        }
    };
} } } }