// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// This example shows how to use a UserTrace to monitor WPP providers.
// This is a special case due slight differences in the event format,
// and the lack of schema information.

using System;
using System.Runtime.InteropServices;
using Microsoft.O365.Security.ETW;

namespace ManagedExamples
{
    public static class WppTrace001
    {
        public static void Start()
        {
            var trace = new UserTrace();

            // WPP providers are basically legacy providers without a registered MOF.
            // They are intended for (internal) debugging purposes only.
            // Note - WPP software tracing has been superceded by TraceLogging.
            //
            // Instead of a manifest or MOF, a separate trace message format (TMF) 
            // file is required to interpret the WPP event data.
            // https://docs.microsoft.com/en-us/windows-hardware/drivers/devtest/trace-message-format-file
            //
            // In some cases, the TMF is included in the PDB.
            // https://docs.microsoft.com/en-us/windows-hardware/drivers/devtest/tracepdb
            //
            // Otherwise, you can attempt to reconstruct the TMF by hand.
            // https://posts.specterops.io/data-source-analysis-and-dynamic-windows-re-using-wpp-and-tracelogging-e465f8b653f7
            //
            // Luckily, WPP tracing is usually added using Microsoft's convenience macros.
            // And, when you have symbols available, WPP metadata is then fairly straightfoward to extract.
            // https://docs.microsoft.com/en-us/windows-hardware/drivers/devtest/adding-wpp-software-tracing-to-a-windows-driver

            // Each WPP trace provider defines a control GUID that uniquely identifies that provider.
            // https://docs.microsoft.com/en-us/windows-hardware/drivers/devtest/control-guid
            //
            // The WPP macros generate control GUID globals named "WPP_ThisDir_CTLGUID_<name>"
            //
            // For example, this control GUID in the symbols for combase.dll
            // WPP_ThisDir_CTLGUID_OLE32 = bda92ae8-9f11-4d49-ba1d-a4c2abca692e
            var ole32WppProvider = new Provider(Guid.Parse("{bda92ae8-9f11-4d49-ba1d-a4c2abca692e}"));

            // We use the control GUID to enable WPP tracing for the provider, and to set 
            // the filtering level and flags.
            // 
            // In evntrace.h there are ten defined trace levels -
            // TRACE_LEVEL_NONE        0   // Tracing is not on
            // TRACE_LEVEL_CRITICAL    1   // Abnormal exit or termination
            // TRACE_LEVEL_ERROR       2   // Severe errors that need logging
            // TRACE_LEVEL_WARNING     3   // Warnings such as allocation failure
            // TRACE_LEVEL_INFORMATION 4   // Includes non-error cases(e.g.,Entry-Exit)
            // TRACE_LEVEL_VERBOSE     5   // Detailed traces from intermediate steps
            // TRACE_LEVEL_RESERVED6   6
            // TRACE_LEVEL_RESERVED7   7
            // TRACE_LEVEL_RESERVED8   8
            // TRACE_LEVEL_RESERVED9   9
            //
            // Microsoft WPP providers are known to use the reserved levels.
            // Internally, these levels have names like CHATTY, GARRULOUS and LOQUACIOUS.
            //
            // Everything at or below the configured level will be traced.
            // Technically 9 means trace everything, but the field is a UCHAR 
            // so 0xFF means definitely trace everything.
            ole32WppProvider.Level = 0xFF;  // 'TRACE_LEVEL_ALL'

            // Flags is a user-defined bitmask field the developer can use to group
            // related messages. 
            // Again, it is a UCHAR for WPP providers so 0xFF means trace everything.
            ole32WppProvider.Any   = 0xFF;  // 'TRACE_FLAGS_ALL'

            // WPP events are also a slightly different format to the modern ETW events. In particular,
            // they include a message GUID rather than the control GUID. In order to convince krabs to
            // forward events to us, we need to register an extra 'provider' using the message GUID.
            //
            // The WPP macros generate message GUID globals named "WPP_<guid>_Traceguids"
            //
            // For example, these message GUIDs in the symbols for combase.dll
            // WPP_c0e4dd87b1523146a49921a43cd25160_Traceguids = c0e4dd87-b152-3146-a499-21a43cd25160
            // WPP_c1647dce9b833d97edb9721fff5f0606_Traceguids = c1647dce-9b83-3d97-edb9-721fff5f0606
            var messageGuid_S = new Provider(Guid.Parse("{c0e4dd87-b152-3146-a499-21a43cd25160}"));
            messageGuid_S.OnEvent += (record) =>
            {
                // krabs does not currently support TMF files for parsing WPP messages.
                // Instead you need to manually parse the UserData.
                //
                // The WPP macros generate logging staging functions named "WPP_SF_<format specifiers>"
                // In this case this message GUID is always associate with a WPP_SF_S(...) call.
                // This tells us that the event contains a single unicode string.
                var message = Marshal.PtrToStringUni(record.UserData);
                Console.WriteLine($"Id:{record.Id} WPP_SF_S({message})");
            };

            var messageGuid_ssdDsS = new Provider(Guid.Parse("{c1647dce-9b83-3d97-edb9-721fff5f0606}"));
            messageGuid_ssdDsS.OnEvent += (record) =>
            {
                // WPP_SF_ssdDsS(...) 
                var userData = record.UserData;
                var string_1 = Marshal.PtrToStringAnsi(userData);
                userData += string_1.Length+1;
                var string_2 = Marshal.PtrToStringAnsi(userData);
                userData += string_2.Length+1;
                var int32_3 = Marshal.ReadInt32(userData);
                userData += sizeof(Int32);
                var uint32_4 = (UInt32)Marshal.ReadInt32(userData);
                userData += sizeof(UInt32);
                var string_5 = Marshal.PtrToStringAnsi(userData);
                userData += string_5.Length+1;
                var string_6 = Marshal.PtrToStringUni(userData);
                Console.WriteLine($"Id:{record.Id} WPP_SF_ssdDsS({string_1}, {string_2}, {int32_3}, {uint32_4}, {string_5}, {string_6})");
            };
            
            // Side note - if you want to turn up the verbosity of your COM WPP diagnostic tracing, then enable
            // OLE32 tracing via the registry following the instruction here -
            // https://support.microsoft.com/en-us/help/926098/how-to-enable-com-and-com-diagnostic-tracing
            //
            // Alternatively call _ControlTracing (4) via combase's 18f70770-8e64-11cf-9af1-0020af6e72f4 RPC interface.

            trace.Enable(ole32WppProvider);
            trace.Enable(messageGuid_S);
            trace.Enable(messageGuid_ssdDsS);
            trace.Start();
        }
    }
}
