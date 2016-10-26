// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Diagnostics.Tracing;
using System.Threading;
using System.Threading.Tasks;

using O365.Security.ETW;

namespace SampleKrabsCSharpExe
{
    // TODO: Example for ETW source latency
    public class TestEventSource : EventSource
    {
        public const int LatencyPing = 1;
        public static readonly TestEventSource Log = new TestEventSource();

        public void Test(int serial)
        {
            WriteEvent(LatencyPing, serial);
        }
    }

    class Program
    {
        public static void HandlePing(IEventRecordMetadata e)
        {
            if (e.Id != TestEventSource.LatencyPing) return;

            var now = DateTime.UtcNow;
            var delta = now - e.Timestamp;

            var data = e.CopyUserData();
            var serial = BitConverter.ToInt32(data, 0);

            Console.WriteLine($"Event {serial} latency {delta.TotalMilliseconds}");
        }

        public static async Task PrintStats(UserTrace t, CancellationToken token)
        {
            while (!token.IsCancellationRequested)
            {
                var stats = t.QueryStats();
                Console.WriteLine($"Stats - Handled:{stats.EventsHandled}. Lost:{stats.EventsLost}");
                await Task.Delay(5000, token);
            }
        }

        static void Main(string[] args)
        {
            var count = 0;
            var cts = new CancellationTokenSource();
            var trace = new UserTrace("MY AWESOME TEST THING");
            //var provider = new RawProvider(EventSource.GetGuid(typeof(TestEventSource)));

            var provider = new Provider(Guid.Parse("{A0C1853B-5C40-4B15-8766-3CF1C58F985A}"));

            // Only pull in method invocations
            var powershellFilter = new EventFilter(Filter.EventIdIs(7937)
                                                    .And(UnicodeString.Contains("Payload", "Started")));

            powershellFilter.OnEvent += e =>
            {
                Console.WriteLine($"{e.ProviderName} - {e.Id}: {count++}");
            };

            provider.AddFilter(powershellFilter);

            Console.CancelKeyPress += (s, e) =>
            {
                cts.Cancel();
                trace.Stop();
            };

            trace.Enable(provider);

            var statsLoop = Task.Run(() => PrintStats(trace, cts.Token));

            Task.Run(() => trace.Start())
                .ContinueWith(t => Console.WriteLine($"Task ended with status {t.Status}"));

            Console.WriteLine("Enter to restart trace");
            Console.ReadKey();

            Task.Run(() => trace.Start())
                .ContinueWith(t => Console.WriteLine($"Task ended with status {t.Status}"));

            Console.WriteLine("Ctrl+C to quit");
            statsLoop.Wait();

            Console.WriteLine("Done");
        }
    }
}