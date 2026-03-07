// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// This example demonstrates reading the ProcessStartKey from ETW extended data items.
// The ProcessStartKey uniquely identifies a process instance across a boot session
// (unlike PID which can be recycled).

using System;
using System.Security.Principal;
using System.Threading;
using Microsoft.O365.Security.ETW;

namespace ManagedExamples
{
    public static class UserTrace008_ProcessStartKey
    {
        public static void Start()
        {
            if (!(new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator)))
            {
                Console.WriteLine("Microsoft-Windows-Kernel-Process provider requires Administrator privileges.");
                return;
            }

            var trace = new UserTrace("UserTrace008_ProcessStartKey");
            var provider = new Provider("Microsoft-Windows-Kernel-Process");
            provider.Any = 0x10; // WINEVENT_KEYWORD_PROCESS
            provider.TraceFlags |= TraceFlags.IncludeProcessStartKey;

            int eventCount = 0;
            int eventsWithKey = 0;
            const int maxEvents = 10;

            // Listen for ProcessStart (1) and ProcessStop (2)
            var filter = new EventFilter(Filter.EventIdIs(1).Or(Filter.EventIdIs(2)));
            filter.OnEvent += (record) =>
            {
                var pid = record.GetUInt32("ProcessID");
                string imageName;
                try { imageName = record.GetUnicodeString("ImageName"); }
                catch { try { imageName = record.GetAnsiString("ImageName"); } catch { imageName = "<unknown>"; } }

                ulong processStartKey = 0;
                bool hasKey = record.TryGetProcessStartKey(out processStartKey);

                if (hasKey && processStartKey != 0)
                    Interlocked.Increment(ref eventsWithKey);

                int count = Interlocked.Increment(ref eventCount);

                Console.WriteLine($"[{record.TaskName}] PID={pid} ImageName={imageName} " +
                                  $"HasProcessStartKey={hasKey} ProcessStartKey=0x{processStartKey:X}");

                if (count >= maxEvents)
                {
                    Console.WriteLine($"\nReceived {count} events, {eventsWithKey} had a non-zero ProcessStartKey.");
                    if (eventsWithKey > 0)
                        Console.WriteLine("PASS: ProcessStartKey is being populated in extended data.");
                    else
                        Console.WriteLine("FAIL: No events had a ProcessStartKey set.");
                    trace.Stop();
                }
            };

            provider.AddFilter(filter);
            trace.Enable(provider);

            Console.WriteLine("Listening for process start/stop events (will stop after 10 events)...");
            Console.WriteLine("Tip: Start or stop some processes to generate events.\n");
            trace.Start();
        }
    }
}
