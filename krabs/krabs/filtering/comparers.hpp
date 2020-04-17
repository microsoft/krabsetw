// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma once

#if(_MANAGED)
#pragma warning(push)
#pragma warning(disable: 4800) // bool warning in boost when _MANAGED flag is set
#endif

#include <algorithm>

#include "../compiler_check.hpp"

#if(_MANAGED)
#pragma warning(pop)
#endif

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
                return std::search(begin1, end1, begin2, end2, Comparer()) != end1;
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
                const auto dist1 = std::distance(begin1, end1);
                const auto dist2 = std::distance(begin2, end2);

                // always starts with empty range
                if (dist2 == 0)
                    return true;

                if (dist2 > dist1)
                    return false;

                auto prefix_end = begin1;
                std::advance(prefix_end, dist2);

                return std::equal(begin1, prefix_end, begin2, end2, Comparer());
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

                // always ends with empty range
                if (dist2 == 0)
                    return true;

                if (dist2 > dist1)
                    return false;

                auto suffix_begin = begin1;
                std::advance(suffix_begin, dist1 - dist2);

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