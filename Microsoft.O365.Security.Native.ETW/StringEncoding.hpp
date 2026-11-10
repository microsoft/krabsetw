// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma once

#include <krabs.hpp>
#include <vcclr.h>
#include "Errors.hpp"

namespace Microsoft { namespace O365 { namespace Security { namespace ETW { namespace details {

#pragma managed(push, off)

    inline UINT string_code_page(USHORT type)
    {
        return type == TDH_OUTTYPE_UTF8 || type == TDH_OUTTYPE_JSON ? CP_UTF8 : CP_ACP;
    }

    inline UINT string_code_page(const TRACE_EVENT_INFO* info, std::wstring_view name)
    {
        for (ULONG i = 0; i < info->TopLevelPropertyCount; ++i) {
            const auto& property = info->EventPropertyInfoArray[i];
            const auto property_name = reinterpret_cast<const wchar_t*>(
                reinterpret_cast<const BYTE*>(info) + property.NameOffset);
            if (name == property_name && (property.Flags & PropertyStruct) == 0) {
                return string_code_page(property.nonStructType.OutType);
            }
        }
        return CP_ACP;
    }

    inline std::string encode_string(const std::wstring& value, UINT code_page)
    {
        if (value.empty())
            return {};
        const auto size = WideCharToMultiByte(code_page, 0, value.data(),
            static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
        if (size == 0)
            throw std::runtime_error("String encoding failed");
        std::string result(size, '\0');
        if (WideCharToMultiByte(code_page, 0, value.data(), static_cast<int>(value.size()),
            result.data(), size, nullptr, nullptr) == 0)
            throw std::runtime_error("String encoding failed");
        return result;
    }

#pragma managed(pop)

    inline System::String^ decode_string(const std::string& value, UINT code_page)
    {
        if (value.empty())
            return System::String::Empty;
        const auto size = MultiByteToWideChar(code_page, 0, value.data(),
            static_cast<int>(value.size()), nullptr, 0);
        if (size == 0)
            throw gcnew ParserException("String decoding failed");
        // Fill only this newly allocated, unpublished string.
        auto result = gcnew System::String(L'\0', size);
        pin_ptr<const wchar_t> pinned = PtrToStringChars(result);
        const wchar_t* buffer = pinned;
        if (MultiByteToWideChar(code_page, 0, value.data(), static_cast<int>(value.size()),
            const_cast<wchar_t*>(buffer), size) == 0)
            throw gcnew ParserException("String decoding failed");
        return result;
    }

} } } } }
