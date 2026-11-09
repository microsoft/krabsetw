// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma once

#ifndef  WIN32_LEAN_AND_MEAN
#define  WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <tdh.h>
#include <evntrace.h>

#include "compiler_check.hpp"

namespace krabs {

    // TODO: I don't like this interface - it's too tightly
    // coupled to parser.hpp mainly because the code was
    // lifted directly out of parser::find_property.

    class size_provider {
    public:
        /**
         * <summary>
         * Get the size of the specified property from the specified record.
         * </summary>
         * BYTE* offset into the user data buffer where the property starts
         * wchar_t* name of the property to query
         * EVENT_RECORD& record to query
         * EVENT_PROPERTY_INFO& property info for the property to query
         */
        static ULONG get_property_size(
            const BYTE*,
            const wchar_t*,
            const EVENT_RECORD&,
            const EVENT_PROPERTY_INFO&);

        /**
         * <summary>
         * Get the size of the specified property if it can be determined from
         * the schema alone, i.e. without inspecting the event payload.
         * Returns 0 if the size depends on the payload.
         * </summary>
         * EVENT_PROPERTY_INFO& property info for the property to query
         * ULONG pointer size (4 or 8) of the event
         */
        static ULONG get_fixed_property_size(
            const EVENT_PROPERTY_INFO&,
            ULONG pointerSize);

        /**
         * <summary>
         * Get the pointer size (4 or 8) of the specified record.
         * </summary>
         */
        static ULONG get_pointer_size(const EVENT_RECORD&);

    private:
        static ULONG get_heuristic_size(
            const BYTE*,
            const EVENT_PROPERTY_INFO&,
            const EVENT_RECORD&);

        static ULONG get_tdh_size(
            const wchar_t*,
            const EVENT_RECORD&);
    };

    // Implementation
    // ------------------------------------------------------------------------

    inline ULONG size_provider::get_property_size(
        const BYTE* propertyStart,
        const wchar_t* propertyName,
        const EVENT_RECORD& record,
        const EVENT_PROPERTY_INFO& propertyInfo)
    {
        if ((propertyInfo.Flags & PropertyStruct) != 0) {
            throw std::runtime_error("Struct properties are not supported");
        }

        // The values of the event are essentially stored as an ad-hoc
        // variant. In order to determine how far we need to advance the
        // seeking pointer, we need to know the size of the property that
        // we've just looked at. For certain variable-sized types (like a
        // string), we need to ask Tdh* to determine the length of the
        // property. For others, the size is immediately accessible in
        // the schema structure.

        ULONG propertyLength = get_fixed_property_size(propertyInfo, get_pointer_size(record));
        if (propertyLength > 0)
        {
            return propertyLength;
        }

        // If no flags are set on the property, attempt to use the length
        // field. If that field is 0, try using our heuristic.
        if (propertyInfo.Flags == 0)
        {
            if (propertyInfo.length > 0)
                propertyLength = propertyInfo.length;
            else
                propertyLength = get_heuristic_size(propertyStart, propertyInfo, record);
        }

        // Couldn't get the length from the 'length' field or
        // the heuristic for size failed -> ask Tdh.
        if (propertyLength == 0)
            propertyLength = get_tdh_size(propertyName, record);

        return propertyLength;
    }

    inline ULONG size_provider::get_fixed_property_size(
        const EVENT_PROPERTY_INFO& propertyInfo,
        ULONG pointerSize)
    {
        if ((propertyInfo.Flags & (PropertyParamLength | PropertyStruct)) == 0 &&
            propertyInfo.length > 0)
        {
            // length is a union that may refer to another field for a length
            // value. In that case, defer to TDH for the value otherwise
            // use the length value directly.

            // For pointer-sized types check header instead of size, see PointerSize at
            // https://docs.microsoft.com/en-us/windows/win32/api/tdh/nf-tdh-tdhformatproperty
            // for details
            if (propertyInfo.nonStructType.InType == TDH_INTYPE_POINTER ||
                propertyInfo.nonStructType.InType == TDH_INTYPE_SIZET)
            {
                return pointerSize;
            }

            return propertyInfo.nonStructType.InType == TDH_INTYPE_UNICODESTRING
                ? propertyInfo.length * sizeof(wchar_t)
                : propertyInfo.length;
        }

        return 0;
    }

    inline ULONG size_provider::get_pointer_size(const EVENT_RECORD& record)
    {
        return record.EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER ? 4 : 8;
    }

    inline ULONG size_provider::get_heuristic_size(
        const BYTE* propertyStart,
        const EVENT_PROPERTY_INFO& propertyInfo,
        const EVENT_RECORD& record)
    {
        ULONG propertyLength = 0;
        PBYTE pRecordEnd = (PBYTE)record.UserData + record.UserDataLength;

        // The calls to Tdh are kind of expensive, especially when krabs is
        // included in a managed assembly as this call will be a thunk.
        // The following _very_ common property types can be short-circuited
        // to prevent the expensive call.

        // Be careful! Check IN and OUT types before making an assumption.

        // Strings that appear at the end of a record may not be null-terminated.
        // If a string is null-terminated, propertyLength includes the null character.
        // If a string is not-null terminated, propertyLength includes all bytes up
        // to the end of the record buffer.

        if (propertyInfo.nonStructType.OutType == TDH_OUTTYPE_STRING)
        {
            if (propertyInfo.nonStructType.InType == TDH_INTYPE_UNICODESTRING)
            {
                auto p = (const wchar_t*)propertyStart;
                auto pEnd = (const wchar_t*)pRecordEnd;
                while (p < pEnd) {
                    if (!*p++) {
                        break;
                    }
                }
                propertyLength = static_cast<ULONG>(((PBYTE)p) - propertyStart);
            }
            else if (propertyInfo.nonStructType.InType == TDH_INTYPE_ANSISTRING)
            {
                auto p = (const char*)propertyStart;
                auto pEnd = (const char*)pRecordEnd;
                while (p < pEnd) {
                    if (!*p++) {
                        break;
                    }

                }
                propertyLength = static_cast<ULONG>(((PBYTE)p) - propertyStart);
            }
        }

        return propertyLength;
    }

    inline ULONG size_provider::get_tdh_size(
        const wchar_t* propertyName,
        const EVENT_RECORD& record)
    {
        ULONG propertyLength = 0;

        PROPERTY_DATA_DESCRIPTOR desc;
        desc.PropertyName = (ULONGLONG)propertyName;
        desc.ArrayIndex = ULONG_MAX;

        auto status = TdhGetPropertySize((PEVENT_RECORD)&record, 0, NULL, 1, &desc, &propertyLength);
        if (status != ERROR_SUCCESS)
            throw std::runtime_error("Failed to get property size from TDH");

        return propertyLength;
    }
}