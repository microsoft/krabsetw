// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// This example demonstrates collecting stack traces as part of events.

using System;
using Microsoft.O365.Security.ETW;

namespace ManagedExamples
{
    public static class UserTrace007_StackTrace
    {
        public static void Start()
        {
            var trace = new UserTrace("UserTrace007_StackTrace");
            var provider = new Provider("Microsoft-Windows-Kernel-Process");
            provider.Any = 0x10;  // WINEVENT_KEYWORD_PROCESS
            provider.TraceFlags |= TraceFlags.IncludeStackTrace;

            var processFilter = new EventFilter(Filter.EventIdIs(1));  // ProcessStart
            processFilter.OnEvent += (record) =>
            {
                var pid = record.GetUInt32("ProcessID");
                var imageName = record.GetUnicodeString("ImageName");
                Console.WriteLine($"{record.TaskName} pid={pid} ImageName={imageName}\nCallStack:");
                foreach (var returnAddress in record.StackTrace())
                {
                    Console.WriteLine($"    0x{returnAddress.ToUInt64():x}");
                }
            };
            provider.AddFilter(processFilter);

            trace.Enable(provider);
            trace.Start();
        }
    }
}
