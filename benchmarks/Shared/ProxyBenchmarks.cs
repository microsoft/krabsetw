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
    /// parity suite already compiles against both. The arms guarded by PURE are the
    /// exception: the ref API has no C++/CLI counterpart, so those cells are empty on that
    /// side by construction rather than by omission.
    ///
    /// Driving events through Testing.Proxy rather than a live session is what makes the
    /// comparison meaningful: a real ETW session would mostly measure the kernel's buffering
    /// and flush cadence, which is identical for both and would swamp the difference being
    /// measured. The path under test is everything from the trace's event callback inwards:
    /// provider matching, schema resolution, predicate evaluation and property decoding.
    ///
    /// Two event shapes are measured, because the cost profile depends on the payload:
    ///
    ///   DNS         a real Microsoft-Windows-DNS-Client resolution, reading the three
    ///               properties HostIDS's DnsResolutionProducer reads. Two of them are
    ///               UTF-16 strings, which is where the C++/CLI wrapper pays twice --
    ///               payload to std::wstring, then std::wstring to System::String.
    ///   Network     eight small fixed-width integers, shaped after a kernel TCP send. No
    ///               copying to speak of, so what is left is the per-property lookup.
    /// </remarks>
    [MemoryDiagnoser]
    public class ProxyBenchmarks
    {
        /// <summary>
        /// Microsoft-Windows-DNS-Client, event 3008 version 0 (query completed). This is
        /// the event HostIDS's DnsResolutionProducer consumes, and the shape below is the
        /// real one: the property names, order and in-types were taken from a live capture
        /// of this provider rather than from the manifest, which ships no templates for it.
        /// </summary>
        private static readonly Guid DnsProviderId =
            Guid.Parse("1c95126e-7eea-49a9-a3fe-a378b03ddb4d");

        /// <summary>
        /// Microsoft-Windows-Kernel-Network, event 11 version 0 (TCP receive): eight small
        /// fixed-width integers and no strings. TDH resolves this from the kernel schema
        /// rather than from a manifest template, so it decodes despite the manifest carrying
        /// no template for it. HostIDS consumes this provider raw -- through OnMetadata, not
        /// because it cannot be decoded, but to avoid the allocation decoding would cost --
        /// which is what the metadata arm below measures.
        /// </summary>
        private static readonly Guid NetworkProviderId =
            Guid.Parse("7DD42A49-5329-4832-8DFD-43D979153A88");

        // Anonymised, but sized from the capture. Across 789 real event 3008 records:
        // QueryName ran 11-76 chars (median 31, mean 30.6); QueryResults was empty on 46%
        // of them and, when present, ran 10-390 chars (median 10, mean 27.1). The values
        // below are a successful A-record lookup returning a single address, which is the
        // modal non-empty case -- and the only one that does any work in HostIDS, which
        // returns early when QueryResults is blank. Reserved .test names (RFC 6761) and
        // documentation addresses are used so nothing real is checked in.
        private const string QueryNameText = "shared.prod.ingest.contoso.test";

        private const string NoMatchNameText = "shared.prod.ingest.contoso.invalid";

        private const string QueryResultsText = "::ffff:10.20.30.40;";

        private const uint DnsQueryType = 1;          // A
        private const ulong DnsQueryOptions = 32784;  // the value on 706 of 789 captured records
        private const uint DnsQueryStatus = 0;        // success

        private const uint NetPid = 4321;
        private const uint NetSize = 1460;
        private const uint NetDestAddr = 167772161; // 10.0.0.1
        private const ushort NetDestPort = 443;

        private SynthRecord _dnsRecord;
        private SynthRecord _netRecord;

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

        private Proxy _dnsMetadataProxy;
        private Proxy _dnsDispatchProxy;
        private Proxy _dnsDecodeProxy;
        private Proxy _dnsMatchProxy;
        private Proxy _dnsRejectProxy;

        private Proxy _netMetadataProxy;
        private Proxy _netDispatchProxy;
        private Proxy _netDecodeProxy;
        private Proxy _netMatchProxy;
        private Proxy _netRejectProxy;

#if PURE
        private Proxy _dnsDispatchRefProxy;
        private Proxy _dnsDecodeRefProxy;
        private Proxy _dnsMatchRefProxy;
        private Proxy _dnsRejectRefProxy;

        private Proxy _netDispatchRefProxy;
        private Proxy _netDecodeRefProxy;
        private Proxy _netMatchRefProxy;
        private Proxy _netRejectRefProxy;

        private Proxy _dnsInlineMatchRefProxy;
        private Proxy _dnsInlineRejectRefProxy;
        private Proxy _netInlineMatchRefProxy;
        private Proxy _netInlineRejectRefProxy;
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

        private static int DnsDecodeSum
        {
            get { return QueryNameText.Length + (int)DnsQueryType + QueryResultsText.Length; }
        }

        private static int NetDecodeSum
        {
            get { return (int)(NetPid + NetSize + NetDestAddr + NetDestPort); }
        }

        [GlobalSetup]
        public void Setup()
        {
            _dnsRecord = CreateDnsRecord();
            _netRecord = CreateNetworkRecord();

            // ---- DNS shape --------------------------------------------------------

            _dnsMetadataProxy = MakeMetadataProxy(DnsProviderId);

            _dnsDispatchProxy = MakeTraceProxy(DnsProviderId, record => { _sink++; });

            // Exactly what DnsResolutionProducer.OnDnsResolutionEvent reads, in its order.
            _dnsDecodeProxy = MakeTraceProxy(DnsProviderId, record =>
            {
                _sink += record.GetUnicodeString("QueryName").Length;
                _sink += (int)record.GetUInt32("QueryType");
                _sink += record.GetUnicodeString("QueryResults").Length;
            });

            _dnsMatchProxy = MakeFilterProxy(
                DnsProviderId, UnicodeString.Is("QueryName", QueryNameText));

            _dnsRejectProxy = MakeFilterProxy(
                DnsProviderId, UnicodeString.Is("QueryName", NoMatchNameText));

            // ---- Network shape ----------------------------------------------------

            _netMetadataProxy = MakeMetadataProxy(NetworkProviderId);

            _netDispatchProxy = MakeTraceProxy(NetworkProviderId, record => { _sink++; });

            _netDecodeProxy = MakeTraceProxy(NetworkProviderId, record =>
            {
                _sink += (int)record.GetUInt32("PID");
                _sink += (int)record.GetUInt32("size");
                _sink += (int)record.GetUInt32("daddr");
                _sink += record.GetUInt16("dport");
            });
            _netMatchProxy = MakeFilterProxy(
                NetworkProviderId, Filter.IsUInt32("PID", NetPid));

            _netRejectProxy = MakeFilterProxy(
                NetworkProviderId, Filter.IsUInt32("PID", NetPid + 1));

#if PURE
            _dnsDispatchRefProxy = MakeRefTraceProxy(
                DnsProviderId, (in EventRecordRef record) => { _sink++; });

            _dnsDecodeRefProxy = MakeRefTraceProxy(DnsProviderId, (in EventRecordRef record) =>
            {
                // No accessor on the ref surface throws; the Get* forms take a default.
                _sink += record.GetUnicodeString("QueryName".AsSpan(), default).Length;
                _sink += (int)record.GetUInt32("QueryType".AsSpan(), 0);
                _sink += record.GetUnicodeString("QueryResults".AsSpan(), default).Length;
            });

            _dnsMatchRefProxy = MakeRefFilterProxy(
                DnsProviderId, UnicodeString.Is("QueryName", QueryNameText));

            _dnsRejectRefProxy = MakeRefFilterProxy(
                DnsProviderId, UnicodeString.Is("QueryName", NoMatchNameText));

            _netDispatchRefProxy = MakeRefTraceProxy(
                NetworkProviderId, (in EventRecordRef record) => { _sink++; });

            _netDecodeRefProxy = MakeRefTraceProxy(NetworkProviderId, (in EventRecordRef record) =>
            {
                // No accessor on the ref surface throws; the Get* forms take a default.
                _sink += (int)record.GetUInt32("PID".AsSpan(), 0);
                _sink += (int)record.GetUInt32("size".AsSpan(), 0);
                _sink += (int)record.GetUInt32("daddr".AsSpan(), 0);
                _sink += record.GetUInt16("dport".AsSpan(), 0);
            });

            _netMatchRefProxy = MakeRefFilterProxy(
                NetworkProviderId, Filter.IsUInt32("PID", NetPid));

            _netRejectRefProxy = MakeRefFilterProxy(
                NetworkProviderId, Filter.IsUInt32("PID", NetPid + 1));

            // The alternative to an EventFilter once handlers no longer allocate: do the
            // test inside the handler. Same decision, same event, no filter object.
            _dnsInlineMatchRefProxy = MakeRefTraceProxy(
                DnsProviderId, (in EventRecordRef record) =>
                {
                    if (record.GetUnicodeString("QueryName".AsSpan(), default)
                        .SequenceEqual(QueryNameText.AsSpan()))
                    {
                        _sink++;
                    }
                });

            _dnsInlineRejectRefProxy = MakeRefTraceProxy(
                DnsProviderId, (in EventRecordRef record) =>
                {
                    if (record.GetUnicodeString("QueryName".AsSpan(), default)
                        .SequenceEqual(NoMatchNameText.AsSpan()))
                    {
                        _sink++;
                    }
                });

            _netInlineMatchRefProxy = MakeRefTraceProxy(
                NetworkProviderId, (in EventRecordRef record) =>
                {
                    if (record.TryGetUInt32("PID".AsSpan(), out uint pid) && pid == NetPid)
                    {
                        _sink++;
                    }
                });

            _netInlineRejectRefProxy = MakeRefTraceProxy(
                NetworkProviderId, (in EventRecordRef record) =>
                {
                    if (record.TryGetUInt32("PID".AsSpan(), out uint pid) && pid == NetPid + 1)
                    {
                        _sink++;
                    }
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
            Check("Dns_Metadata", () => _dnsMetadataProxy.PushEvent(_dnsRecord), 1);
            Check("Dns_Dispatch", () => _dnsDispatchProxy.PushEvent(_dnsRecord), 1);
            Check("Dns_Decode", () => _dnsDecodeProxy.PushEvent(_dnsRecord), DnsDecodeSum);
            Check("Dns_FilterMatch", () => _dnsMatchProxy.PushEvent(_dnsRecord), 1);
            Check("Dns_FilterReject", () => _dnsRejectProxy.PushEvent(_dnsRecord), 0);

            Check("Network_Metadata", () => _netMetadataProxy.PushEvent(_netRecord), 1);
            Check("Network_Dispatch", () => _netDispatchProxy.PushEvent(_netRecord), 1);
            Check("Network_Decode", () => _netDecodeProxy.PushEvent(_netRecord), NetDecodeSum);
            Check("Network_FilterMatch", () => _netMatchProxy.PushEvent(_netRecord), 1);
            Check("Network_FilterReject", () => _netRejectProxy.PushEvent(_netRecord), 0);

#if PURE
            Check("Dns_DispatchRef", () => _dnsDispatchRefProxy.PushEvent(_dnsRecord), 1);
            Check("Dns_DecodeRef", () => _dnsDecodeRefProxy.PushEvent(_dnsRecord), DnsDecodeSum);
            Check("Dns_FilterMatchRef", () => _dnsMatchRefProxy.PushEvent(_dnsRecord), 1);
            Check("Dns_FilterRejectRef", () => _dnsRejectRefProxy.PushEvent(_dnsRecord), 0);

            Check("Network_DispatchRef", () => _netDispatchRefProxy.PushEvent(_netRecord), 1);
            Check("Network_DecodeRef", () => _netDecodeRefProxy.PushEvent(_netRecord), NetDecodeSum);
            Check("Network_FilterMatchRef", () => _netMatchRefProxy.PushEvent(_netRecord), 1);
            Check("Network_FilterRejectRef", () => _netRejectRefProxy.PushEvent(_netRecord), 0);

            Check("Dns_InlineMatchRef", () => _dnsInlineMatchRefProxy.PushEvent(_dnsRecord), 1);
            Check("Dns_InlineRejectRef", () => _dnsInlineRejectRefProxy.PushEvent(_dnsRecord), 0);
            Check("Network_InlineMatchRef", () => _netInlineMatchRefProxy.PushEvent(_netRecord), 1);
            Check("Network_InlineRejectRef", () => _netInlineRejectRefProxy.PushEvent(_netRecord), 0);
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

        private static SynthRecord CreateDnsRecord()
        {
            using (var rb = new RecordBuilder(DnsProviderId, 3008, 0))
            {
                rb.AddUnicodeString("QueryName", QueryNameText);
                rb.AddValue<uint>("QueryType", DnsQueryType);
                rb.AddValue<ulong>("QueryOptions", DnsQueryOptions);
                rb.AddValue<uint>("QueryStatus", DnsQueryStatus);
                rb.AddUnicodeString("QueryResults", QueryResultsText);

                return rb.Pack();
            }
        }

        /// <summary>
        /// Microsoft-Windows-Kernel-Network event 11 (TCP receive), with the real property
        /// names and types. The counterweight to the DNS record, where decode cost is
        /// almost entirely copying.
        /// </summary>
        private static SynthRecord CreateNetworkRecord()
        {
            using (var rb = new RecordBuilder(NetworkProviderId, 11, 0))
            {
                rb.AddValue<uint>("PID", NetPid);
                rb.AddValue<uint>("size", NetSize);
                rb.AddValue<uint>("daddr", NetDestAddr);
                rb.AddValue<uint>("saddr", 167772162);
                rb.AddValue<ushort>("dport", NetDestPort);
                rb.AddValue<ushort>("sport", 51314);
                rb.AddValue<uint>("seqnum", 987654);
                rb.AddValue<uint>("connid", 12345);

                return rb.Pack();
            }
        }

        /// <summary>
        /// A provider with only an OnMetadata handler. Nothing on this path resolves a
        /// schema, on either implementation, so it measures delivery and header access
        /// alone -- the floor for a consumer that reads the payload itself.
        /// </summary>
        private Proxy MakeMetadataProxy(Guid providerId)
        {
            var trace = new UserTrace();
            var proxy = new Proxy(trace);

            var provider = new Provider(providerId);
            provider.OnMetadata += record =>
            {
                // Header-only access, all of it available without a schema.
                _sink += record.ProcessId == uint.MaxValue ? 2 : 1;
                _sink += record.Id == ushort.MaxValue ? 1 : 0;
                _sink += record.UserDataLength == ushort.MaxValue ? 1 : 0;
            };

            trace.Enable(provider);

            _roots.Add(trace);
            _roots.Add(provider);
            return proxy;
        }

        private Proxy MakeTraceProxy(Guid providerId, IEventRecordDelegate handler)
        {
            var trace = new UserTrace();
            var proxy = new Proxy(trace);

            var provider = new Provider(providerId);
            provider.OnEvent += handler;

            trace.Enable(provider);

            _roots.Add(trace);
            _roots.Add(provider);
            return proxy;
        }

        private Proxy MakeFilterProxy(Guid providerId, Predicate predicate)
        {
            var trace = new UserTrace();
            var proxy = new Proxy(trace);

            var provider = new Provider(providerId);

            var filter = new EventFilter(predicate);
            filter.OnEvent += record => { _sink++; };

            provider.AddFilter(filter);
            trace.Enable(provider);

            _roots.Add(trace);
            _roots.Add(provider);
            _roots.Add(filter);
            return proxy;
        }

#if PURE
        /// <summary>
        /// The same wiring as <see cref="MakeTraceProxy"/>, but through the ref API. Only
        /// the pure .NET port has one, so these arms have no C++/CLI counterpart.
        /// </summary>
        private Proxy MakeRefTraceProxy(Guid providerId, EventRecordDelegate handler)
        {
            var trace = new UserTrace();
            var proxy = new Proxy(trace);

            var provider = new Provider(providerId);
            provider.OnEventRef += handler;

            trace.Enable(provider);

            _roots.Add(trace);
            _roots.Add(provider);
            return proxy;
        }

        /// <summary>
        /// The same wiring as <see cref="MakeFilterProxy"/>, but the filter's handler is the
        /// ref one. The predicate is identical, so this isolates the cost of the handler
        /// surface rather than of filtering.
        /// </summary>
        private Proxy MakeRefFilterProxy(Guid providerId, Predicate predicate)
        {
            var trace = new UserTrace();
            var proxy = new Proxy(trace);

            var provider = new Provider(providerId);

            var filter = new EventFilter(predicate);
            filter.OnEventRef += (in EventRecordRef record) => { _sink++; };

            provider.AddFilter(filter);
            trace.Enable(provider);

            _roots.Add(trace);
            _roots.Add(provider);
            _roots.Add(filter);
            return proxy;
        }
#endif

        // ---- DNS shape -----------------------------------------------------------

        /// <summary>Delivery and header access only. No schema is resolved.</summary>
        [Benchmark]
        public void Dns_Metadata()
        {
            _dnsMetadataProxy.PushEvent(_dnsRecord);
        }

        /// <summary>
        /// The floor for the compat surface: provider matching and callback delivery, no
        /// payload access. A schema is still resolved, because IEventRecord exposes
        /// schema-derived members with no failure channel and so may not be handed to a
        /// handler without one.
        /// </summary>
        [Benchmark]
        public void Dns_Dispatch()
        {
            _dnsDispatchProxy.PushEvent(_dnsRecord);
        }

        /// <summary>
        /// Reads the two strings and the integer HostIDS reads, in its order. QueryResults
        /// is the last of the five properties, so reaching it walks the offsets of every
        /// preceding one -- which is the realistic cost, not a best case.
        /// </summary>
        [Benchmark]
        public void Dns_Decode()
        {
            _dnsDecodeProxy.PushEvent(_dnsRecord);
        }

        /// <summary>A string predicate that matches, so the comparison runs to completion.</summary>
        [Benchmark]
        public void Dns_FilterMatch()
        {
            _dnsMatchProxy.PushEvent(_dnsRecord);
        }

        /// <summary>
        /// A string predicate that rejects. The common case in production, where filters
        /// exist precisely to discard most events.
        /// </summary>
        [Benchmark]
        public void Dns_FilterReject()
        {
            _dnsRejectProxy.PushEvent(_dnsRecord);
        }

        // ---- Network shape --------------------------------------------------------

        [Benchmark]
        public void Network_Metadata()
        {
            _netMetadataProxy.PushEvent(_netRecord);
        }

        [Benchmark]
        public void Network_Dispatch()
        {
            _netDispatchProxy.PushEvent(_netRecord);
        }

        /// <summary>
        /// Four fixed-width integers. Nothing is copied, so this measures per-property
        /// lookup rather than marshalling.
        /// </summary>
        [Benchmark]
        public void Network_Decode()
        {
            _netDecodeProxy.PushEvent(_netRecord);
        }

        [Benchmark]
        public void Network_FilterMatch()
        {
            _netMatchProxy.PushEvent(_netRecord);
        }

        [Benchmark]
        public void Network_FilterReject()
        {
            _netRejectProxy.PushEvent(_netRecord);
        }

#if PURE
        // ---- Ref surface, no C++/CLI counterpart ----------------------------------

        /// <summary>
        /// The header-only handler through the ref surface. Unlike the compat one this does
        /// not resolve a schema, because EventRecordRef reports an unreadable property
        /// through TryGet/Get rather than needing one up front. The gap between the two is
        /// what a consumer that never decodes saves.
        /// </summary>
        [Benchmark]
        public void Dns_DispatchRef()
        {
            _dnsDispatchRefProxy.PushEvent(_dnsRecord);
        }

        /// <summary>The same properties, read as spans rather than materialised.</summary>
        [Benchmark]
        public void Dns_DecodeRef()
        {
            _dnsDecodeRefProxy.PushEvent(_dnsRecord);
        }

        /// <summary>
        /// The predicate is payload-tier, so a schema is resolved for the predicate either
        /// way. Only the handler surface differs.
        /// </summary>
        [Benchmark]
        public void Dns_FilterMatchRef()
        {
            _dnsMatchRefProxy.PushEvent(_dnsRecord);
        }

        /// <summary>
        /// The predicate rejects, so no handler runs on either surface. Expected to match
        /// the compat arm; it is here to show that, not because it can differ.
        /// </summary>
        [Benchmark]
        public void Dns_FilterRejectRef()
        {
            _dnsRejectRefProxy.PushEvent(_dnsRecord);
        }

        [Benchmark]
        public void Network_DispatchRef()
        {
            _netDispatchRefProxy.PushEvent(_netRecord);
        }

        [Benchmark]
        public void Network_DecodeRef()
        {
            _netDecodeRefProxy.PushEvent(_netRecord);
        }

        [Benchmark]
        public void Network_FilterMatchRef()
        {
            _netMatchRefProxy.PushEvent(_netRecord);
        }

        [Benchmark]
        public void Network_FilterRejectRef()
        {
            _netRejectRefProxy.PushEvent(_netRecord);
        }

        // ---- The same decision without an EventFilter ------------------------------

        /// <summary>
        /// EventFilter exists because rejecting an event before a managed EventRecord was
        /// materialised avoided the allocation. A ref handler allocates nothing, so the
        /// filter's original justification does not apply to it -- these arms measure the
        /// same predicate written inline in the handler instead, which is what a ref
        /// consumer would otherwise do.
        /// </summary>
        [Benchmark]
        public void Dns_InlineFilterMatchRef()
        {
            _dnsInlineMatchRefProxy.PushEvent(_dnsRecord);
        }

        /// <summary>
        /// The reject case is the one that matters: a filter's whole purpose is to discard
        /// cheaply, so this is where an EventFilter has to beat an inline test to be worth
        /// keeping on the ref path.
        /// </summary>
        [Benchmark]
        public void Dns_InlineFilterRejectRef()
        {
            _dnsInlineRejectRefProxy.PushEvent(_dnsRecord);
        }

        [Benchmark]
        public void Network_InlineFilterMatchRef()
        {
            _netInlineMatchRefProxy.PushEvent(_netRecord);
        }

        [Benchmark]
        public void Network_InlineFilterRejectRef()
        {
            _netInlineRejectRefProxy.PushEvent(_netRecord);
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
