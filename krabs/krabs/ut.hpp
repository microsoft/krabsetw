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
		
		struct FilterSettings
		{
			std::vector<unsigned short> m_OrigEventIds;
			std::tuple<UCHAR, ULONGLONG, ULONGLONG, UCHAR> flagsTuple;
		};

		typedef std::map<krabs::guid, FilterSettings> ProvidersFilterSettings;
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
		ProvidersFilterSettings	providerFlags;

		// This function essentially takes the union of all the provider flags
		// for a given provider GUID. This comes about when multiple providers
		// for the same GUID are provided and request different provider flags.
		// TODO: Only forward the calls that are requested to each provider.
        for (auto &provider : trace.providers_) {
            if (providerFlags.find(provider.get().guid_) != providerFlags.end()) {
                providerFlags[provider.get().guid_].flagsTuple = std::make_tuple<UCHAR, ULONGLONG, ULONGLONG, UCHAR> (0, 0, 0, 0);
            }

			std::get<0>(providerFlags[provider.get().guid_].flagsTuple) |= provider.get().level_;
			std::get<1>(providerFlags[provider.get().guid_].flagsTuple) |= provider.get().any_;
			std::get<2>(providerFlags[provider.get().guid_].flagsTuple) |= provider.get().all_;
			std::get<3>(providerFlags[provider.get().guid_].flagsTuple) |= provider.get().trace_flags_;

			for(const auto& filter : provider.get().filters_)
			{
				if (filter.OrigEventId() > 0)
				{
					//native id existing, set native filters
					providerFlags[provider.get().guid_].m_OrigEventIds.push_back(filter.OrigEventId());
				}
			}
		}

		for (auto &provider : providerFlags) {
			//compose native event params by native events ids 
			ENABLE_TRACE_PARAMETERS parameters;
			ZeroMemory(&parameters, sizeof(parameters));
			parameters.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
			parameters.SourceId = provider.first;

			GUID guid = provider.first;
			parameters.EnableProperty = std::get<3>(provider.second.flagsTuple);
			parameters.EnableFilterDesc = nullptr;
			parameters.FilterDescCount = 0;
			EVENT_FILTER_DESCRIPTOR filterDesc;
			std::unique_ptr<BYTE[]> filterMemoryPtr;

			if (provider.second.m_OrigEventIds.size() > 0)
			{
				//event filters existing, se native filters using API
				parameters.FilterDescCount = 1;  

				ZeroMemory(&filterDesc, sizeof(filterDesc));
				filterDesc.Type = EVENT_FILTER_TYPE_EVENT_ID;

				//allocate + size of expected events in filter
				DWORD size = FIELD_OFFSET(EVENT_FILTER_EVENT_ID, Events[provider.second.m_OrigEventIds.size()]);
				filterMemoryPtr = std::make_unique<BYTE[]>(size);

				auto filterEventIds = reinterpret_cast<PEVENT_FILTER_EVENT_ID>(filterMemoryPtr.get());
				filterEventIds->FilterIn = TRUE;
				filterEventIds->Count = static_cast<USHORT>(provider.second.m_OrigEventIds.size());
				for(int index=0;index<filterEventIds->Count;++index)
				{
					filterEventIds->Events[index] = provider.second.m_OrigEventIds[index];
				}
				filterDesc.Ptr = reinterpret_cast<ULONGLONG>(filterEventIds);
				filterDesc.Size = size;

				parameters.EnableFilterDesc = &filterDesc;
			}
			
			ULONG status = EnableTraceEx2(trace.registrationHandle_,
										&guid,
										EVENT_CONTROL_CODE_ENABLE_PROVIDER,
										std::get<0>(provider.second.flagsTuple),
										std::get<1>(provider.second.flagsTuple),
										std::get<2>(provider.second.flagsTuple),
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
