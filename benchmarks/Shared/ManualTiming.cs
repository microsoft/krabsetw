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

            Console.WriteLine("{0,-22} {1,12} {2,14} {3,12}", "Method", "ns/event", "bytes/event", "sink/event");

            Time(bench, "Dispatch", bench.Dispatch);
            Time(bench, "DecodeThreeStrings", bench.DecodeThreeStrings);
            Time(bench, "FilterMatch", bench.FilterMatch);
            Time(bench, "FilterReject", bench.FilterReject);
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
            // printing a number that looks like a very good result.
            if (sinkDelta == 0 && name != "FilterReject")
            {
                throw new InvalidOperationException(
                    name + " measured nothing: the handler did not run during the loop.");
            }
        }
    }
}
