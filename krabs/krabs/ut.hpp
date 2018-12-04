// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma once

#include "compiler_check.hpp"
#include "trace.hpp"
#include "provider.hpp"

namespace krabs { namespace details {

    /**
     * <summary>
     *   Used as a template argument to a trace instance. This class implements
     *   code paths for user traces. Should never be used or seen by client
     *   code.
     * </summary>
     */
    struct ut {

        typedef krabs::provider<> provider_type;
        
        struct filter_settings{
            std::vector<unsigned short> provider_filter_event_ids_;
            std::tuple<UCHAR, ULONGLONG, ULONGLONG, UCHAR> flags_tuple_;
        };

        typedef std::map<krabs::guid, filter_settings> provider_filter_settings;
        /**
         * <summary>
         *   Used to assign a name to the trace instance that is being
         *   instantiated.
         * </summary>
         * <remarks>
         *   There really isn't a name policy to enforce with user traces, but
         *   kernel traces do have specific naming requirements.
         * </remarks>
         */
        static const std::wstring enforce_name_policy(
            const std::wstring &name);

        /**
         * <summary>
         *   Generates a value that fills the EnableFlags field in an
         *   EVENT_TRACE_PROPERTIES structure. This controls the providers that
         *   get enabled for a kernel trace. For a user trace, it doesn't do
         *   much of anything.
         * </summary>
         */
        static const unsigned long construct_enable_flags(
            const krabs::trace<krabs::details::ut> &trace);

        /**
         * <summary>
         *   Enables the providers that are attached to the given trace.
         * </summary>
         */
        static void enable_providers(
            const krabs::trace<krabs::details::ut> &trace);

        /**
         * <summary>
         *   Decides to forward an event to any of the providers in the trace.
         * </summary>
         */
        static void forward_events(
            const EVENT_RECORD &record,
            const krabs::trace<krabs::details::ut> &trace);

        /**
         * <summary>
         *   Sets the ETW trace log file mode.
         * </summary>
         */
        static unsigned long augment_file_mode();

        /**
         * <summary>
         *   Returns the GUID of the trace session.
         * </summary>
         */
        static krabs::guid get_trace_guid();
    };


    // Implementation
    // ------------------------------------------------------------------------

    inline const std::wstring ut::enforce_name_policy(
        const std::wstring &name_hint)
    {
        if (name_hint.empty()) {
            return std::to_wstring(krabs::guid::random_guid());
        }

        return name_hint;
    }

    inline const unsigned long ut::construct_enable_flags(
        const krabs::trace<krabs::details::ut> &)
    {
        return 0;
    }

    inline void ut::enable_providers(
        const krabs::trace<krabs::details::ut> &trace)
    {
        provider_filter_settings provider_flags;

        // This function essentially takes the union of all the provider flags
        // for a given provider GUID. This comes about when multiple providers
        // for the same GUID are provided and request different provider flags.
        // TODO: Only forward the calls that are requested to each provider.
        for (auto &provider : trace.providers_) {
            if (provider_flags.find(provider.get().guid_) != provider_flags.end()) {
                provider_flags[provider.get().guid_].flags_tuple_ = std::make_tuple<UCHAR, ULONGLONG, ULONGLONG, UCHAR> (0, 0, 0, 0);
            }

            std::get<0>(provider_flags[provider.get().guid_].flags_tuple_) |= provider.get().level_;
            std::get<1>(provider_flags[provider.get().guid_].flags_tuple_) |= provider.get().any_;
            std::get<2>(provider_flags[provider.get().guid_].flags_tuple_) |= provider.get().all_;
            std::get<3>(provider_flags[provider.get().guid_].flags_tuple_) |= provider.get().trace_flags_;

            for (const auto& filter : provider.get().filters_) {
                if (filter.provider_filter_event_id() > 0) {
                	//native id existing, set native filters
					auto& provider_filter_event_ids = provider_flags[provider.get().guid_].provider_filter_event_ids_;
					provider_filter_event_ids.push_back(filter.provider_filter_event_id()); 
                }
            }
        }

        for (auto &provider : provider_flags) {
            ENABLE_TRACE_PARAMETERS parameters;
            parameters.ControlFlags = 0;
            parameters.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
            parameters.SourceId = provider.first;
            
            GUID guid = provider.first;
            parameters.EnableProperty = std::get<3>(provider.second.flags_tuple_);
            parameters.EnableFilterDesc = nullptr;
            parameters.FilterDescCount = 0;
            EVENT_FILTER_DESCRIPTOR filterDesc;
            std::unique_ptr<BYTE[]> filterMemoryPtr;

            if (provider.second.provider_filter_event_ids_.size() > 0) {
                //event filters existing, set native filters using API
                parameters.FilterDescCount = 1;  

                ZeroMemory(&filterDesc, sizeof(filterDesc));
                filterDesc.Type = EVENT_FILTER_TYPE_EVENT_ID;

                //allocate + size of expected events in filter
                DWORD size = FIELD_OFFSET(EVENT_FILTER_EVENT_ID, Events[provider.second.provider_filter_event_ids_.size()]);
                filterMemoryPtr = std::make_unique<BYTE[]>(size);

                auto filterEventIds = reinterpret_cast<PEVENT_FILTER_EVENT_ID>(filterMemoryPtr.get());
                filterEventIds->FilterIn = TRUE;
                filterEventIds->Count = static_cast<USHORT>(provider.second.provider_filter_event_ids_.size());
                for (int index=0;index<filterEventIds->Count;++index) {
                	filterEventIds->Events[index] = provider.second.provider_filter_event_ids_[index];
                }
                filterDesc.Ptr = reinterpret_cast<ULONGLONG>(filterEventIds);
                filterDesc.Size = size;

                parameters.EnableFilterDesc = &filterDesc;
            }

            ULONG status = EnableTraceEx2(trace.registrationHandle_,
                                        &guid,
                                        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                                        std::get<0>(provider.second.flags_tuple_),
                                        std::get<1>(provider.second.flags_tuple_),
                                        std::get<2>(provider.second.flags_tuple_),
                                        0,
                                        &parameters);
            UNREFERENCED_PARAMETER(status);
        }
    }

    inline void ut::forward_events(
        const EVENT_RECORD &record,
        const krabs::trace<krabs::details::ut> &trace)
    {
        for (auto &provider : trace.providers_) {
            if (record.EventHeader.ProviderId == provider.get().guid_) {
                provider.get().on_event(record);
            }
        }
    }

    inline unsigned long ut::augment_file_mode()
    {
        return 0;
    }

    inline krabs::guid ut::get_trace_guid()
    {
        return krabs::guid::random_guid();
    }

} /* namespace details */ } /* namespace krabs */
