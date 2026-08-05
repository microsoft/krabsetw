using System;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Jobs;
using BenchmarkDotNet.Running;
using Microsoft.O365.Security.ETW.Interop;
using Microsoft.O365.Security.ETW.Schema;

namespace Microsoft.O365.Security.ETW.Benchmarks
{
    /// <summary>
    /// Measures the per-event cost of the dispatch path over captured records.
    /// </summary>
    /// <remarks>
    /// The memory diagnoser is the point of these benchmarks as much as the timings:
    /// any non-zero allocation on the span path is a regression against the design goal.
    /// </remarks>
    [MemoryDiagnoser]
    public unsafe class DispatchBenchmarks
    {
        private CapturedRecords _captured;
        private EVENT_RECORD*[] _records;
        private EventScratch _scratch;
        private EventRecordAdapter _adapter;

        private Predicate _headerPredicate;
        private Predicate _stringPredicate;

        [GlobalSetup]
        public void Setup()
        {
            _captured = CapturedRecords.Capture(256);
            _records = _captured.Records;
            _scratch = new EventScratch();
            _adapter = new EventRecordAdapter();

            _headerPredicate = Filter.EventOpcodeIs(0);
            _stringPredicate = UnicodeString.Is("message", "benchmark payload");

            // A cache miss per event would invalidate every payload measurement below.
            for (int i = 0; i < _records.Length; i++)
            {
                _scratch.Begin(_records[i]);
                var record = new EventRecordRef(_records[i], _scratch);
                GC.KeepAlive(record.PropertyCount);
            }

            Console.WriteLine("Captured " + _records.Length + " records, schema misses = " + _scratch.SchemaMisses);
        }

        [GlobalCleanup]
        public void Cleanup()
        {
            _scratch.Dispose();
            _captured.Dispose();
        }

        /// <summary>
        /// The floor: what it costs to present a record without touching the payload.
        /// </summary>
        [Benchmark(Baseline = true)]
        public int HeaderOnly()
        {
            int total = 0;
            for (int i = 0; i < _records.Length; i++)
            {
                _scratch.Begin(_records[i]);
                var record = new EventRecordRef(_records[i], _scratch);
                total += record.Id;
            }

            return total;
        }

        /// <summary>
        /// A header-only predicate must not force schema resolution.
        /// </summary>
        [Benchmark]
        public int HeaderPredicate()
        {
            int matched = 0;
            for (int i = 0; i < _records.Length; i++)
            {
                _scratch.Begin(_records[i]);
                var record = new EventRecordRef(_records[i], _scratch);
                if (_headerPredicate.Test(in record))
                {
                    matched++;
                }
            }

            return matched;
        }

        /// <summary>
        /// Isolates schema lookup: how much of the decode cost is finding the schema rather
        /// than reading the payload.
        /// </summary>
        [Benchmark]
        public int SchemaLookupOnly()
        {
            int total = 0;
            for (int i = 0; i < _records.Length; i++)
            {
                _scratch.Begin(_records[i]);
                var record = new EventRecordRef(_records[i], _scratch);
                total += record.PropertyCount;
            }

            return total;
        }

        /// <summary>
        /// A string predicate compares in place; no string is materialised.
        /// </summary>
        [Benchmark]
        public int StringPredicate()
        {
            int matched = 0;
            for (int i = 0; i < _records.Length; i++)
            {
                _scratch.Begin(_records[i]);
                var record = new EventRecordRef(_records[i], _scratch);
                if (_stringPredicate.Test(in record))
                {
                    matched++;
                }
            }

            return matched;
        }

        /// <summary>
        /// The span path: read every property without allocating.
        /// </summary>
        [Benchmark]
        public int DecodeViaSpan()
        {
            int total = 0;
            for (int i = 0; i < _records.Length; i++)
            {
                _scratch.Begin(_records[i]);
                var record = new EventRecordRef(_records[i], _scratch);

                if (record.TryGetUnicodeString("message".AsSpan(), out ReadOnlySpan<char> message))
                {
                    total += message.Length;
                }

                if (record.TryGetInt32("number".AsSpan(), out int number))
                {
                    total += number;
                }

                if (record.TryGetInt64("identifier".AsSpan(), out long identifier))
                {
                    total += (int)identifier;
                }
            }

            return total;
        }

        /// <summary>
        /// The compatibility path: same work through IEventRecord, which materialises
        /// managed strings exactly as the C++/CLI implementation did.
        /// </summary>
        [Benchmark]
        public int DecodeViaCompatInterface()
        {
            int total = 0;
            for (int i = 0; i < _records.Length; i++)
            {
                _scratch.Begin(_records[i]);
                _adapter.Begin(_records[i], _scratch);
                IEventRecord record = _adapter;

                total += record.GetUnicodeString("message").Length;
                total += record.GetInt32("number");
                total += (int)record.GetInt64("identifier");

                _adapter.End();
            }

            return total;
        }
    }

    public static class Program
    {
        public static void Main(string[] args)
        {
            BenchmarkRunner.Run<DispatchBenchmarks>(
                DefaultConfig.Instance.AddJob(Job.Default.WithId("default")),
                args);
        }
    }
}
