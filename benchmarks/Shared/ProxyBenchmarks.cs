// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Running;

using Microsoft.O365.Security.ETW;
using Microsoft.O365.Security.ETW.Testing;

namespace Krabs.Benchmarks
{
    /// <summary>
    /// The head-to-head benchmark. This one source file is compiled twice: once against the
    /// C++/CLI wrapper and once against the pure .NET port.
    /// </summary>
    /// <remarks>
    /// It uses only API that both implementations expose, which is exactly the API the
    /// parity suite already compiles against both. Driving events through Testing.Proxy
    /// rather than a live session is what makes the comparison meaningful: a real ETW
    /// session would mostly measure the kernel's buffering and flush cadence, which is
    /// identical for both and would swamp the difference being measured.
    ///
    /// The path under test is everything from the trace's event callback inwards: provider
    /// matching, schema resolution, predicate evaluation and property decoding.
    /// </remarks>
    [MemoryDiagnoser]
    public class ProxyBenchmarks
    {
        private static readonly Guid ProviderId =
            Guid.Parse("a0c1853b-5c40-4b15-8766-3cf1c58f985a");

        private const string PayloadText =
            "a representative payload string, long enough that copying it is not free";

        private SynthRecord _record;

        /// <summary>
        /// Traces and providers are rooted deliberately.
        /// </summary>
        /// <remarks>
        /// Proxy does not keep the trace it wraps alive, so a trace held only by a local
        /// is collectable the moment the constructor returns. When that happens PushEvent
        /// silently delivers nothing, which shows up as an implausibly fast, allocation
        /// free benchmark rather than as an error.
        /// </remarks>
        private readonly List<object> _roots = new List<object>();

        private Proxy _dispatchProxy;
        private Proxy _decodeProxy;
        private Proxy _matchingFilterProxy;
        private Proxy _rejectingFilterProxy;
#if PURE
        private Proxy _decodeRefProxy;
#endif

        private int _sink;

        /// <summary>
        /// Exposed so the manual harness can confirm the handlers ran for every iteration,
        /// not just the first one.
        /// </summary>
        public int Sink
        {
            get { return _sink; }
        }

        [GlobalSetup]
        public void Setup()
        {
            _record = CreateRecord();

            _dispatchProxy = MakeTraceProxy(record => { _sink++; });

            _decodeProxy = MakeTraceProxy(record =>
            {
                _sink += record.GetUnicodeString("UserData").Length;
                _sink += record.GetUnicodeString("ContextInfo").Length;
                _sink += record.GetUnicodeString("Payload").Length;
            });

            _matchingFilterProxy = MakeFilterProxy(
                UnicodeString.Is("Payload", PayloadText));

            _rejectingFilterProxy = MakeFilterProxy(
                UnicodeString.Is("Payload", PayloadText + " no match"));

#if PURE
            _decodeRefProxy = MakeRefTraceProxy((in EventRecordRef record) =>
            {
                _sink += record.GetUnicodeString("UserData".AsSpan()).Length;
                _sink += record.GetUnicodeString("ContextInfo".AsSpan()).Length;
                _sink += record.GetUnicodeString("Payload".AsSpan()).Length;
            });
#endif

            VerifyWiring();
        }

        /// <summary>
        /// Fails loudly if the handlers are not actually being invoked.
        /// </summary>
        /// <remarks>
        /// Without this a misconfigured proxy silently measures an empty PushEvent and
        /// reports an implausibly fast, allocation-free result. That is a benchmark
        /// reporting success while measuring nothing, which is worse than no benchmark.
        /// </remarks>
        private void VerifyWiring()
        {
            Check("Dispatch", () => _dispatchProxy.PushEvent(_record), 1);
            Check(
                "DecodeThreeStrings",
                () => _decodeProxy.PushEvent(_record),
                "user data".Length + "context info".Length + PayloadText.Length);
            Check("FilterMatch", () => _matchingFilterProxy.PushEvent(_record), 1);
            Check("FilterReject", () => _rejectingFilterProxy.PushEvent(_record), 0);
#if PURE
            Check(
                "DecodeThreeStringsRef",
                () => _decodeRefProxy.PushEvent(_record),
                "user data".Length + "context info".Length + PayloadText.Length);
#endif
        }

        private void Check(string name, Action push, int expectedDelta)
        {
            int before = _sink;
            push();
            int delta = _sink - before;

            if (delta != expectedDelta)
            {
                throw new InvalidOperationException(
                    name + " is not wired up: expected the handler to add " + expectedDelta +
                    " to the sink, but it added " + delta + ".");
            }
        }

        private static SynthRecord CreateRecord()
        {
            using (var rb = new RecordBuilder(ProviderId, 7937, 1))
            {
                rb.AddUnicodeString("UserData", "user data");
                rb.AddUnicodeString("ContextInfo", "context info");
                rb.AddUnicodeString("Payload", PayloadText);

                return rb.Pack();
            }
        }

        private Proxy MakeTraceProxy(IEventRecordDelegate handler)
        {
            var trace = new UserTrace();
            var proxy = new Proxy(trace);

            var provider = new Provider(ProviderId);
            provider.OnEvent += handler;

            trace.Enable(provider);

            _roots.Add(trace);
            _roots.Add(provider);
            return proxy;
        }

#if PURE
        /// <summary>
        /// The same wiring as <see cref="MakeTraceProxy"/>, but through the ref API. Only
        /// the pure .NET port has one, so this arm has no C++/CLI counterpart to compare
        /// against -- it exists to show what the same decode costs once the three strings
        /// are read as spans instead of being materialised.
        /// </summary>
        private Proxy MakeRefTraceProxy(EventRecordDelegate handler)
        {
            var trace = new UserTrace();
            var proxy = new Proxy(trace);

            var provider = new Provider(ProviderId);
            provider.OnEventRef += handler;

            trace.Enable(provider);

            _roots.Add(trace);
            _roots.Add(provider);
            return proxy;
        }
#endif

        private Proxy MakeFilterProxy(Predicate predicate)        {
            var trace = new UserTrace();
            var proxy = new Proxy(trace);

            var provider = new Provider(ProviderId);

            var filter = new EventFilter(predicate);
            filter.OnEvent += record => { _sink++; };

            provider.AddFilter(filter);
            trace.Enable(provider);

            _roots.Add(trace);
            _roots.Add(provider);
            _roots.Add(filter);
            return proxy;
        }

        /// <summary>
        /// The floor: provider matching and callback delivery, no payload access.
        /// </summary>
        [Benchmark(Baseline = true)]
        public void Dispatch()
        {
            _dispatchProxy.PushEvent(_record);
        }

        /// <summary>
        /// Reads three string properties. This is the path most consumers are on, and the
        /// one where the C++/CLI wrapper pays for a double copy: payload to std::wstring,
        /// then std::wstring to System::String.
        /// </summary>
        [Benchmark]
        public void DecodeThreeStrings()
        {
            _decodeProxy.PushEvent(_record);
        }

        /// <summary>
        /// A string predicate that matches, so the comparison runs to completion.
        /// </summary>
        [Benchmark]
        public void FilterMatch()
        {
            _matchingFilterProxy.PushEvent(_record);
        }

        /// <summary>
        /// A string predicate that rejects. The common case in production, where filters
        /// exist precisely to discard most events.
        /// </summary>
        [Benchmark]
        public void FilterReject()
        {
            _rejectingFilterProxy.PushEvent(_record);
        }

#if PURE
        /// <summary>
        /// The same three strings as <see cref="DecodeThreeStrings"/>, read as spans. The
        /// only cell in this file with no C++/CLI counterpart.
        /// </summary>
        [Benchmark]
        public void DecodeThreeStringsRef()
        {
            _decodeRefProxy.PushEvent(_record);
        }
#endif
    }

    public static class Program
    {
        public static void Main(string[] args)
        {
            if (args.Length > 0 && args[0] == "--manual")
            {
                ManualTiming.Run();
                return;
            }

            BenchmarkRunner.Run<ProxyBenchmarks>(null, args);
        }
    }
}
