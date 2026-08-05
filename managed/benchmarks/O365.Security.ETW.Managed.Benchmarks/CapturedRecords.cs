using System;
using System.Collections.Generic;
using System.Diagnostics.Tracing;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.O365.Security.ETW.Interop;

namespace Microsoft.O365.Security.ETW.Benchmarks
{
    /// <summary>
    /// A TraceLogging (self-describing) source. Self-describing events carry their schema
    /// in-band, so TDH can decode them without a system-registered manifest.
    /// </summary>
    internal sealed class BenchmarkEventSource : EventSource
    {
        public const string ProviderName = "Krabs-Managed-Benchmark";

        public static readonly BenchmarkEventSource Log = new BenchmarkEventSource();

        private BenchmarkEventSource()
            : base(ProviderName, EventSourceSettings.EtwSelfDescribingEventFormat)
        {
        }

        public void Interesting(string message, int number, long identifier)
        {
            Write("Interesting", new Payload { message = message, number = number, identifier = identifier });
        }

        [EventData]
        public sealed class Payload
        {
            public string message { get; set; }

            public int number { get; set; }

            public long identifier { get; set; }
        }
    }

    /// <summary>
    /// Captures real EVENT_RECORDs from a live ETW session once, deep-copying each into
    /// unmanaged memory so they can be replayed deterministically.
    /// </summary>
    /// <remarks>
    /// Benchmarking against a live session would measure ETW's own buffering, not this
    /// library. Replaying captured records isolates the code under test: schema lookup,
    /// predicate evaluation and property decoding.
    /// </remarks>
    internal sealed unsafe class CapturedRecords : IDisposable
    {
        private readonly List<IntPtr> _blocks = new List<IntPtr>();

        public EVENT_RECORD*[] Records { get; private set; }

        public static CapturedRecords Capture(int count)
        {
            var captured = new CapturedRecords();
            var records = new List<IntPtr>();
            var signal = new ManualResetEventSlim(false);

            var filter = new EventFilter(Filter.EventNameIs("Interesting"));
            filter.OnEventSpan += (in EventRecordRef record) =>
            {
                if (records.Count >= count)
                {
                    signal.Set();
                    return;
                }

                records.Add((IntPtr)captured.DeepCopy(record.Record));
            };

            // Constructed from the GUID, not the name: an in-process EventSource is not
            // registered with the system, so TdhEnumerateProviders cannot resolve its name.
            // Keyword 0 means "match all". A non-zero mask would collide with the keyword
            // bits EventSource reserves for its own per-session filtering.
            var provider = new Provider(BenchmarkEventSource.Log.Guid) { Any = 0 };
            provider.AddFilter(filter);

            using (var trace = new UserTrace("Krabs-Managed-Bench-" + Guid.NewGuid().ToString("N")))
            {
                trace.Enable(provider);
                trace.Open();

                Task processing = Task.Run(() => trace.Start());

                try
                {
                    DateTime deadline = DateTime.UtcNow + TimeSpan.FromSeconds(30);
                    while (DateTime.UtcNow < deadline && !signal.IsSet)
                    {
                        for (int i = 0; i < 64; i++)
                        {
                            BenchmarkEventSource.Log.Interesting("benchmark payload", i, 0x1122334455667788L);
                        }

                        signal.Wait(TimeSpan.FromMilliseconds(50));
                    }
                }
                finally
                {
                    trace.Stop();
                    processing.Wait(TimeSpan.FromSeconds(30));
                }
            }

            if (records.Count == 0)
            {
                captured.Dispose();
                throw new InvalidOperationException(
                    "No events were captured. The benchmark host must run elevated.");
            }

            var array = new EVENT_RECORD*[records.Count];
            for (int i = 0; i < records.Count; i++)
            {
                array[i] = (EVENT_RECORD*)records[i];
            }

            captured.Records = array;
            return captured;
        }

        private EVENT_RECORD* DeepCopy(EVENT_RECORD* source)
        {
            EVENT_RECORD* copy = (EVENT_RECORD*)Alloc(sizeof(EVENT_RECORD));
            *copy = *source;

            if (source->UserDataLength > 0 && source->UserData != IntPtr.Zero)
            {
                IntPtr userData = Alloc(source->UserDataLength);
                Buffer.MemoryCopy(
                    (void*)source->UserData,
                    (void*)userData,
                    source->UserDataLength,
                    source->UserDataLength);
                copy->UserData = userData;
            }

            int itemCount = source->ExtendedDataCount;
            if (itemCount > 0 && source->ExtendedData != IntPtr.Zero)
            {
                int itemBytes = itemCount * sizeof(EVENT_HEADER_EXTENDED_DATA_ITEM);
                var items = (EVENT_HEADER_EXTENDED_DATA_ITEM*)Alloc(itemBytes);
                var sourceItems = (EVENT_HEADER_EXTENDED_DATA_ITEM*)source->ExtendedData;

                for (int i = 0; i < itemCount; i++)
                {
                    items[i] = sourceItems[i];

                    if (sourceItems[i].DataSize > 0 && sourceItems[i].DataPtr != 0)
                    {
                        IntPtr data = Alloc(sourceItems[i].DataSize);
                        Buffer.MemoryCopy(
                            (void*)(IntPtr)(long)sourceItems[i].DataPtr,
                            (void*)data,
                            sourceItems[i].DataSize,
                            sourceItems[i].DataSize);
                        items[i].DataPtr = (ulong)(long)data;
                    }
                }

                copy->ExtendedData = (IntPtr)items;
            }

            return copy;
        }

        private IntPtr Alloc(int bytes)
        {
            IntPtr block = Marshal.AllocHGlobal(bytes);
            _blocks.Add(block);
            return block;
        }

        public void Dispose()
        {
            foreach (IntPtr block in _blocks)
            {
                Marshal.FreeHGlobal(block);
            }

            _blocks.Clear();
            Records = null;
        }
    }
}
