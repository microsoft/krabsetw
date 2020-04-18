// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma once

#include <algorithm>

#include "../compiler_check.hpp"

namespace krabs { namespace predicates {

    namespace comparers {

        // Algorithms
        // --------------------------------------------------------------------

        /**
         * Iterator based equals
         */
        template <typename Comparer>
        struct equals
        {
            template <typename Iter1, typename Iter2>
            bool operator()(Iter1 begin1, Iter1 end1, Iter2 begin2, Iter2 end2) const
            {
                return std::equal(begin1, end1, begin2, end2, Comparer());
            }
        };

        /**
         * Iterator based search
         */
        template <typename Comparer>
        struct contains
        {
            template <typename Iter1, typename Iter2>
            bool operator()(Iter1 begin1, Iter1 end1, Iter2 begin2, Iter2 end2) const
            {
                // empty test range always contained, even when input range empty
                return std::distance(begin2, end2) == 0 
                    || std::search(begin1, end1, begin2, end2, Comparer()) != end1;
            }
        };

        /**
         * Iterator based starts_with
         */
        template <typename Comparer>
        struct starts_with
        {
            template <typename Iter1, typename Iter2>
            bool operator()(Iter1 begin1, Iter1 end1, Iter2 begin2, Iter2 end2) const
            {
                const auto first_nonequal = std::mismatch(begin1, end1, begin2, end2, Comparer());
                return first_nonequal.second == end2;
            }
        };

        /**
        * Iterator based ends_with
        */
        template <typename Comparer>
        struct ends_with
        {
            template <typename Iter1, typename Iter2>
            bool operator()(Iter1 begin1, Iter1 end1, Iter2 begin2, Iter2 end2) const
            {
                const auto dist1 = std::distance(begin1, end1);
                const auto dist2 = std::distance(begin2, end2);

                if (dist2 > dist1)
                    return false;

                const auto suffix_begin = std::next(begin1, dist1 - dist2);
                return std::equal(suffix_begin, end1, begin2, end2, Comparer());
            }
        };

        // Custom Comparison
        // --------------------------------------------------------------------

        template <typename T>
        struct iequal_to
        {
            bool operator()(const T& a, const T& b) const
            {
                static_assert(sizeof(T) == 0,
                    "iequal_to needs a specialized overload for type");
            }
        };

        /**
        * <summary>
        *   Binary predicate for comparing two wide characters case insensitively
        *   Does not handle all locales
        * </summary>
        */
        template <>
        struct iequal_to<wchar_t>
        {
            bool operator()(const wchar_t& a, const wchar_t& b) const
            {
                return towupper(a) == towupper(b);
            }
        };

        /**
        * <summary>
        *   Binary predicate for comparing two characters case insensitively
        *   Does not handle all locales
        * </summary>
        */
        template <>
        struct iequal_to<char>
        {
            bool operator()(const char& a, const char& b) const
            {
                return toupper(a) == toupper(b);
            }
        };

    } /* namespace comparers */

} /* namespace predicates */ } /* namespace krabs */