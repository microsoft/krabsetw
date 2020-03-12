// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma once

#ifndef  WIN32_LEAN_AND_MEAN
#define  WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>

#include <string>

namespace krabs {

    class dll_helper {
    public:
        explicit dll_helper(const std::wstring& lib)
            : module_(::LoadLibraryW(lib.c_str()))
        {
        }

        ~dll_helper()
        {
            if (module_)
            {
                ::FreeLibrary(module_);
            }
        }

        dll_helper(const dll_helper&) = delete;
        dll_helper& operator=(const dll_helper&) = delete;

        HMODULE get()
        {
            return module_;
        }


    private:
        HMODULE module_ = nullptr;
    };

  
}
