// Emits ground-truth sizes/offsets from the real Windows headers so the C#
// interop definitions can be validated against them.
#define WIN32_LEAN_AND_MEAN
#define INITGUID
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <stdio.h>
#include <stddef.h>

#define P_SIZE(t)      printf("SIZE\t%s\t%zu\n", #t, sizeof(t))
#define P_OFF(t, f)    printf("OFF\t%s.%s\t%zu\n", #t, #f, (size_t)offsetof(t, f))

int main()
{
    P_SIZE(GUID);
    P_SIZE(EVENT_DESCRIPTOR);
    P_SIZE(ETW_BUFFER_CONTEXT);
    P_SIZE(EVENT_HEADER);
    P_SIZE(EVENT_HEADER_EXTENDED_DATA_ITEM);
    P_SIZE(EVENT_RECORD);
    P_SIZE(WNODE_HEADER);
    P_SIZE(EVENT_TRACE_PROPERTIES);
    P_SIZE(EVENT_TRACE_HEADER);
    P_SIZE(EVENT_TRACE);
    P_SIZE(TIME_ZONE_INFORMATION);
    P_SIZE(TRACE_LOGFILE_HEADER);
    P_SIZE(EVENT_TRACE_LOGFILEW);
    P_SIZE(ENABLE_TRACE_PARAMETERS);
    P_SIZE(EVENT_FILTER_DESCRIPTOR);
    P_SIZE(EVENT_FILTER_EVENT_ID);
    P_SIZE(TRACE_EVENT_INFO);
    P_SIZE(EVENT_PROPERTY_INFO);

    P_OFF(EVENT_DESCRIPTOR, Id);
    P_OFF(EVENT_DESCRIPTOR, Version);
    P_OFF(EVENT_DESCRIPTOR, Channel);
    P_OFF(EVENT_DESCRIPTOR, Level);
    P_OFF(EVENT_DESCRIPTOR, Opcode);
    P_OFF(EVENT_DESCRIPTOR, Task);
    P_OFF(EVENT_DESCRIPTOR, Keyword);

    P_OFF(EVENT_HEADER, Size);
    P_OFF(EVENT_HEADER, HeaderType);
    P_OFF(EVENT_HEADER, Flags);
    P_OFF(EVENT_HEADER, EventProperty);
    P_OFF(EVENT_HEADER, ThreadId);
    P_OFF(EVENT_HEADER, ProcessId);
    P_OFF(EVENT_HEADER, TimeStamp);
    P_OFF(EVENT_HEADER, ProviderId);
    P_OFF(EVENT_HEADER, EventDescriptor);
    P_OFF(EVENT_HEADER, ActivityId);

    P_OFF(EVENT_RECORD, EventHeader);
    P_OFF(EVENT_RECORD, BufferContext);
    P_OFF(EVENT_RECORD, ExtendedDataCount);
    P_OFF(EVENT_RECORD, UserDataLength);
    P_OFF(EVENT_RECORD, ExtendedData);
    P_OFF(EVENT_RECORD, UserData);
    P_OFF(EVENT_RECORD, UserContext);

    P_OFF(EVENT_HEADER_EXTENDED_DATA_ITEM, Reserved1);
    P_OFF(EVENT_HEADER_EXTENDED_DATA_ITEM, ExtType);
    P_OFF(EVENT_HEADER_EXTENDED_DATA_ITEM, DataSize);
    P_OFF(EVENT_HEADER_EXTENDED_DATA_ITEM, DataPtr);

    P_OFF(WNODE_HEADER, BufferSize);
    P_OFF(WNODE_HEADER, ProviderId);
    P_OFF(WNODE_HEADER, Guid);
    P_OFF(WNODE_HEADER, ClientContext);
    P_OFF(WNODE_HEADER, Flags);

    P_OFF(EVENT_TRACE_PROPERTIES, Wnode);
    P_OFF(EVENT_TRACE_PROPERTIES, BufferSize);
    P_OFF(EVENT_TRACE_PROPERTIES, MinimumBuffers);
    P_OFF(EVENT_TRACE_PROPERTIES, MaximumBuffers);
    P_OFF(EVENT_TRACE_PROPERTIES, MaximumFileSize);
    P_OFF(EVENT_TRACE_PROPERTIES, LogFileMode);
    P_OFF(EVENT_TRACE_PROPERTIES, FlushTimer);
    P_OFF(EVENT_TRACE_PROPERTIES, EnableFlags);
    P_OFF(EVENT_TRACE_PROPERTIES, NumberOfBuffers);
    P_OFF(EVENT_TRACE_PROPERTIES, FreeBuffers);
    P_OFF(EVENT_TRACE_PROPERTIES, EventsLost);
    P_OFF(EVENT_TRACE_PROPERTIES, BuffersWritten);
    P_OFF(EVENT_TRACE_PROPERTIES, LogBuffersLost);
    P_OFF(EVENT_TRACE_PROPERTIES, RealTimeBuffersLost);
    P_OFF(EVENT_TRACE_PROPERTIES, LoggerThreadId);
    P_OFF(EVENT_TRACE_PROPERTIES, LogFileNameOffset);
    P_OFF(EVENT_TRACE_PROPERTIES, LoggerNameOffset);

    P_OFF(EVENT_TRACE_LOGFILEW, LogFileName);
    P_OFF(EVENT_TRACE_LOGFILEW, LoggerName);
    P_OFF(EVENT_TRACE_LOGFILEW, CurrentTime);
    P_OFF(EVENT_TRACE_LOGFILEW, BuffersRead);
    P_OFF(EVENT_TRACE_LOGFILEW, ProcessTraceMode);
    P_OFF(EVENT_TRACE_LOGFILEW, CurrentEvent);
    P_OFF(EVENT_TRACE_LOGFILEW, LogfileHeader);
    P_OFF(EVENT_TRACE_LOGFILEW, BufferCallback);
    P_OFF(EVENT_TRACE_LOGFILEW, BufferSize);
    P_OFF(EVENT_TRACE_LOGFILEW, Filled);
    P_OFF(EVENT_TRACE_LOGFILEW, EventsLost);
    P_OFF(EVENT_TRACE_LOGFILEW, EventRecordCallback);
    P_OFF(EVENT_TRACE_LOGFILEW, IsKernelTrace);
    P_OFF(EVENT_TRACE_LOGFILEW, Context);

    P_OFF(ENABLE_TRACE_PARAMETERS, Version);
    P_OFF(ENABLE_TRACE_PARAMETERS, EnableProperty);
    P_OFF(ENABLE_TRACE_PARAMETERS, ControlFlags);
    P_OFF(ENABLE_TRACE_PARAMETERS, SourceId);
    P_OFF(ENABLE_TRACE_PARAMETERS, EnableFilterDesc);
    P_OFF(ENABLE_TRACE_PARAMETERS, FilterDescCount);

    P_OFF(EVENT_FILTER_DESCRIPTOR, Ptr);
    P_OFF(EVENT_FILTER_DESCRIPTOR, Size);
    P_OFF(EVENT_FILTER_DESCRIPTOR, Type);

    P_OFF(EVENT_FILTER_EVENT_ID, FilterIn);
    P_OFF(EVENT_FILTER_EVENT_ID, Reserved);
    P_OFF(EVENT_FILTER_EVENT_ID, Count);
    P_OFF(EVENT_FILTER_EVENT_ID, Events);

    P_OFF(TRACE_EVENT_INFO, ProviderGuid);
    P_OFF(TRACE_EVENT_INFO, EventGuid);
    P_OFF(TRACE_EVENT_INFO, EventDescriptor);
    P_OFF(TRACE_EVENT_INFO, DecodingSource);
    P_OFF(TRACE_EVENT_INFO, ProviderNameOffset);
    P_OFF(TRACE_EVENT_INFO, LevelNameOffset);
    P_OFF(TRACE_EVENT_INFO, ChannelNameOffset);
    P_OFF(TRACE_EVENT_INFO, KeywordsNameOffset);
    P_OFF(TRACE_EVENT_INFO, TaskNameOffset);
    P_OFF(TRACE_EVENT_INFO, OpcodeNameOffset);
    P_OFF(TRACE_EVENT_INFO, EventMessageOffset);
    P_OFF(TRACE_EVENT_INFO, ProviderMessageOffset);
    P_OFF(TRACE_EVENT_INFO, BinaryXMLOffset);
    P_OFF(TRACE_EVENT_INFO, BinaryXMLSize);
    P_OFF(TRACE_EVENT_INFO, EventNameOffset);
    P_OFF(TRACE_EVENT_INFO, EventAttributesOffset);
    P_OFF(TRACE_EVENT_INFO, PropertyCount);
    P_OFF(TRACE_EVENT_INFO, TopLevelPropertyCount);
    P_OFF(TRACE_EVENT_INFO, EventPropertyInfoArray);

    P_OFF(EVENT_PROPERTY_INFO, Flags);
    P_OFF(EVENT_PROPERTY_INFO, NameOffset);
    P_OFF(EVENT_PROPERTY_INFO, count);
    P_OFF(EVENT_PROPERTY_INFO, length);

    return 0;
}
