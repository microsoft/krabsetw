// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Diagnostics;

namespace Krabs.Benchmarks
{
    /// <summary>
    /// A plain stopwatch harness, used to sanity-check the BenchmarkDotNet numbers.
    /// </summary>
    /// <remarks>
    /// Not a replacement for BenchmarkDotNet. It exists because a benchmark that reports a
    /// decode costing the same as a no-op is more likely to be a broken measurement than a
    /// free decode, and an independent measurement is the cheapest way to tell which.
    /// </remarks>
    public static class ManualTiming
    {
        public static void Run()
        {
            var bench = new ProxyBenchmarks();
            bench.Setup();

            Console.WriteLine("{0,-32} {1,12} {2,14} {3,12}", "Method", "ns/event", "bytes/event", "sink/event");

            Time(bench, "Dns_Metadata", bench.Dns_Metadata);
            Time(bench, "Dns_Dispatch", bench.Dns_Dispatch);
            Time(bench, "Dns_Decode", bench.Dns_Decode);
            Time(bench, "Dns_FilterMatch", bench.Dns_FilterMatch);
            Time(bench, "Dns_FilterReject", bench.Dns_FilterReject);

            Time(bench, "Network_Metadata", bench.Network_Metadata);
            Time(bench, "Network_Dispatch", bench.Network_Dispatch);
            Time(bench, "Network_Decode", bench.Network_Decode);
            Time(bench, "Network_FilterMatch", bench.Network_FilterMatch);
            Time(bench, "Network_FilterReject", bench.Network_FilterReject);
#if PURE
            Time(bench, "Dns_DispatchRef", bench.Dns_DispatchRef);
            Time(bench, "Dns_DecodeRef", bench.Dns_DecodeRef);
            Time(bench, "Dns_FilterMatchRef", bench.Dns_FilterMatchRef);
            Time(bench, "Dns_FilterRejectRef", bench.Dns_FilterRejectRef);
            Time(bench, "Dns_InlineMatchRef", bench.Dns_InlineFilterMatchRef);
            Time(bench, "Dns_InlineRejectRef", bench.Dns_InlineFilterRejectRef);

            Time(bench, "Network_DispatchRef", bench.Network_DispatchRef);
            Time(bench, "Network_DecodeRef", bench.Network_DecodeRef);
            Time(bench, "Network_FilterMatchRef", bench.Network_FilterMatchRef);
            Time(bench, "Network_FilterRejectRef", bench.Network_FilterRejectRef);
            Time(bench, "Network_InlineMatchRef", bench.Network_InlineFilterMatchRef);
            Time(bench, "Network_InlineRejectRef", bench.Network_InlineFilterRejectRef);
#endif
        }

        private static void Time(ProxyBenchmarks bench, string name, Action action)
        {
            const int Warmup = 20_000;
            const int Iterations = 200_000;

            for (int i = 0; i < Warmup; i++)
            {
                action();
            }

            GC.Collect();
            GC.WaitForPendingFinalizers();
            GC.Collect();

            long before = GC.GetTotalMemory(false);
            int sinkBefore = bench.Sink;
            var sw = Stopwatch.StartNew();

            for (int i = 0; i < Iterations; i++)
            {
                action();
            }

            sw.Stop();
            long after = GC.GetTotalMemory(false);
            int sinkDelta = bench.Sink - sinkBefore;

            double nanos = sw.Elapsed.TotalMilliseconds * 1_000_000.0 / Iterations;
            double bytes = (after - before) / (double)Iterations;

            Console.WriteLine(
                "{0,-22} {1,12:F1} {2,14:F1} {3,12:F1}",
                name,
                nanos,
                bytes,
                sinkDelta / (double)Iterations);

            // A benchmark whose handler never ran measures nothing. Say so rather than
            // printing a number that looks like a very good result. The reject arms are the
            // exception: their whole point is that the predicate discards the event, so a
            // zero sink is the expected outcome rather than a broken measurement.
            if (sinkDelta == 0 && name.IndexOf("Reject", StringComparison.Ordinal) < 0)
            {
                throw new InvalidOperationException(
                    name + " measured nothing: the handler did not run during the loop.");
            }
        }
    }
}
