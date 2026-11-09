// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Diagnostics.Tracing;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.O365.Security.ETW;
using Microsoft.O365.Security.ETW.Testing;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace EtwTestsCS
{
    [TestClass]
    public class describe_CallbackValues
    {
        [TestMethod]
        public void wrappers_are_reused_but_old_enumerables_cannot_bind_to_the_next_event()
        {
            var trace = new UserTrace();
            var provider = new Provider(Events.PowerShellEvent.ProviderId);
            IEventRecord saved = null;
            IEnumerable<Property> properties = null;
            int calls = 0;
            provider.OnEvent += e =>
            {
                ++calls;
                Assert.AreEqual("value", e.GetUnicodeString(Events.PowerShellEvent.UserData));
                if (saved != null)
                {
                    Assert.AreSame(saved, e);
                    Assert.ThrowsException<ObjectDisposedException>(() => properties.GetEnumerator());
                }
                saved = e;
                properties = e.Properties;
            };
            trace.Enable(provider);
            var record = Events.PowerShellEvent.CreateRecord("value", "", "");
            var proxy = new Proxy(trace);
            proxy.PushEvent(record);
            proxy.PushEvent(record);
            Assert.AreEqual(2, calls);
        }

        [TestMethod]
        public void proxy_roots_a_temporary_record_during_gc_in_the_handler()
        {
            var trace = new UserTrace();
            var provider = new Provider(Events.PowerShellEvent.ProviderId);
            WeakReference weak = null;
            bool called = false;
            provider.OnEvent += e =>
            {
                called = true;
                GC.Collect();
                GC.WaitForPendingFinalizers();
                GC.Collect();
                Assert.IsTrue(weak.IsAlive, "The synthetic record was collected during dispatch.");
                Assert.AreEqual("value", e.GetUnicodeString(Events.PowerShellEvent.UserData));
            };
            trace.Enable(provider);
            new Proxy(trace).PushEvent(CreateTemporary(out weak));
            Assert.IsTrue(called);
        }

        [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.NoInlining)]
        private static SynthRecord CreateTemporary(out WeakReference weak)
        {
            var record = Events.PowerShellEvent.CreateRecord("value", "", "");
            weak = new WeakReference(record);
            return record;
        }

        [TestMethod]
        [Timeout(30000)]
        public void live_handler_failure_preserves_identity_stack_and_allows_restart()
        {
            using (var source = new EventSource("krabs-callback-" + Guid.NewGuid(),
                EventSourceSettings.EtwSelfDescribingEventFormat))
            using (var trace = new UserTrace("krabs-callback-trace-" + Guid.NewGuid()))
            {
                var provider = new Provider(source.Guid);
                var expected = new InvalidOperationException("live callback");
                var calls = 0;
                var fail = true;
                provider.OnMetadata += e =>
                {
                    Interlocked.Increment(ref calls);
                    if (fail)
                        ThrowFromHandler(expected);
                };
                trace.Enable(provider);
                for (int run = 0; run < 2; ++run)
                {
                    trace.Open();
                    var processing = Task.Run(() =>
                    {
                        try { trace.Start(); return (Exception)null; }
                        catch (Exception ex) { return ex; }
                    });
                    Exception result;
                    try
                    {
                        for (int i = 0; i < 50 && !processing.IsCompleted && Volatile.Read(ref calls) == 0; ++i)
                        {
                            source.Write("Trigger", new EventSourceOptions { Level = EventLevel.Informational },
                                new { Value = 1 });
                            Thread.Sleep(100);
                        }
                        if (!fail)
                            trace.Stop();
                        Assert.IsTrue(processing.Wait(TimeSpan.FromSeconds(10)),
                            "Processing did not stop after the handler failed.");
                        result = processing.Result;
                        if (fail)
                            Assert.IsFalse(source.IsEnabled(), "Failed processing left the ETW session enabled.");
                    }
                    finally
                    {
                        trace.Stop();
                        Assert.IsTrue(processing.Wait(TimeSpan.FromSeconds(10)));
                    }
                    if (fail)
                    {
                        Assert.AreSame(expected, result);
                        StringAssert.Contains(result.StackTrace, nameof(ThrowFromHandler));
                        Assert.AreEqual(1, calls, "Dispatch continued after the first handler failure.");
                    }
                    else
                    {
                        Assert.IsNull(result);
                        Assert.IsTrue(calls > 0, "Restart did not dispatch any events.");
                    }
                    fail = false;
                    calls = 0;
                }
            }
        }

        [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.NoInlining)]
        private static void ThrowFromHandler(Exception error)
        {
            throw error;
        }

        private static readonly Guid Utf8Provider = new Guid("43833E12-078D-4D7D-8AAF-AE8C8520F18C");

        [TestMethod]
        public void utf8_getter_decodes_literal_bytes()
        {
            var builder = new RecordBuilder(Utf8Provider, 10003, 0);
            builder.AddAnsiString("ExceptionWhatString", "xx");
            var trace = new UserTrace();
            var provider = new Provider(Utf8Provider);
            provider.OnMetadata += e => Marshal.Copy(new byte[] { 0xC3, 0xA9, 0 }, 0, e.UserData, 3);
            provider.OnEvent += e =>
            {
                Assert.AreEqual("\u00e9", e.GetAnsiString("ExceptionWhatString"));
                Assert.IsTrue(e.TryGetAnsiString("ExceptionWhatString", out var value));
                Assert.AreEqual("\u00e9", value);
            };
            trace.Enable(provider);
            new Proxy(trace).PushEvent(builder.Pack());
        }

        [TestMethod]
        public void utf8_builder_writes_utf8_bytes()
        {
            var builder = new RecordBuilder(Utf8Provider, 10003, 0);
            builder.AddAnsiString("ExceptionWhatString", "\u00e9");
            var trace = new UserTrace();
            var provider = new Provider(Utf8Provider);
            provider.OnMetadata += e => CollectionAssert.AreEqual(
                new byte[] { 0xC3, 0xA9, 0 }, e.CopyUserData());
            trace.Enable(provider);
            new Proxy(trace).PushEvent(builder.Pack());
        }

        [TestMethod]
        public void utf8_predicates_match_literal_bytes()
        {
            var builder = new RecordBuilder(Utf8Provider, 10003, 0);
            builder.AddAnsiString("ExceptionWhatString", "xx");
            var record = builder.Pack();
            var trace = new UserTrace();
            var provider = new Provider(Utf8Provider);
            provider.OnMetadata += e => Marshal.Copy(new byte[] { 0xC3, 0xA9, 0 }, 0, e.UserData, 3);
            trace.Enable(provider);
            new Proxy(trace).PushEvent(record);
            Assert.IsTrue(AnsiString.Is("ExceptionWhatString", "\u00e9").Test(record));
            Assert.IsTrue(AnsiString.Contains("ExceptionWhatString", "\u00e9").Test(record));
            Assert.IsTrue(AnsiString.StartsWith("ExceptionWhatString", "\u00e9").Test(record));
            Assert.IsTrue(AnsiString.EndsWith("ExceptionWhatString", "\u00e9").Test(record));
            Assert.IsTrue(AnsiString.IEquals("ExceptionWhatString", "\u00e9").Test(record));
            Assert.IsTrue(AnsiString.IContains("ExceptionWhatString", "\u00e9").Test(record));
            Assert.IsTrue(AnsiString.IStartsWith("ExceptionWhatString", "\u00e9").Test(record));
            Assert.IsTrue(AnsiString.IEndsWith("ExceptionWhatString", "\u00e9").Test(record));
        }

        [TestMethod]
        public void sized_ansi_preserves_embedded_nul()
        {
            var providerId = new Guid("43D1A55C-76D6-4F7E-995C-64C711E5CAFE");
            var builder = new RecordBuilder(providerId, 101, 0);
            builder.AddValue("_UserAgentLength", (ushort)3);
            builder.AddAnsiString("UserAgent", "a\0b");
            var trace = new UserTrace();
            var provider = new Provider(providerId);
            provider.OnEvent += e =>
            {
                Assert.AreEqual("a\0b", e.GetAnsiString("UserAgent"));
                Assert.IsTrue(e.TryGetAnsiString("UserAgent", out var value));
                Assert.AreEqual("a\0b", value);
            };
            trace.Enable(provider);
            new Proxy(trace).PushEvent(builder.PackIncomplete());
        }

        [DataTestMethod]
        [DataRow(0L, true)]
        [DataRow(2650467743999999999L, true)]
        [DataRow(-1L, false)]
        [DataRow(2650467744000000000L, false)]
        public void filetime_range_is_checked(long ticks, bool valid)
        {
            var providerId = new Guid("0888E5EF-9B98-4695-979D-E92CE4247224");
            var builder = new RecordBuilder(providerId, 10000, 0);
            var trace = new UserTrace();
            var provider = new Provider(providerId);
            provider.OnMetadata += e => Marshal.WriteInt64(e.UserData, 4, ticks);
            provider.OnEvent += e =>
            {
                Assert.AreEqual(valid, e.TryGetDateTime("UTCStartTime", out var time));
                if (valid)
                    Assert.AreEqual(DateTime.FromFileTimeUtc(ticks), e.GetDateTime("UTCStartTime"));
                else
                {
                    var fallback = new DateTime(1970, 1, 1);
                    Assert.AreEqual(fallback, e.GetDateTime("UTCStartTime", fallback));
                    Assert.ThrowsException<ParserException>(() => e.GetDateTime("UTCStartTime"));
                }
            };
            trace.Enable(provider);
            new Proxy(trace).PushEvent(builder.PackIncomplete());
        }

        [DataTestMethod]
        [DataRow(0)]
        [DataRow(1)]
        [DataRow(2)]
        [DataRow(16)]
        public void socket_conversion_uses_the_actual_length(int length)
        {
            var providerId = new Guid("0C478C5B-0351-41B1-8C58-4A6737DA32E3");
            var builder = new RecordBuilder(providerId, 1011, 0);
            builder.AddValue("LocalAddressLength", (uint)length);
            var trace = new UserTrace();
            var provider = new Provider(providerId);
            provider.OnMetadata += e =>
            {
                if (length >= 2)
                    Marshal.WriteInt16(e.UserData, 12, 2);
            };
            provider.OnEvent += e =>
            {
                if (length == 0)
                {
                    Assert.IsNull(e.GetSocketAddress("LocalAddress"));
                    Assert.IsFalse(e.TryGetSocketAddress("LocalAddress", out _));
                }
                else if (length == 1)
                {
                    Assert.IsFalse(e.TryGetSocketAddress("LocalAddress", out _));
                    Assert.ThrowsException<ParserException>(() => e.GetSocketAddress("LocalAddress"));
                }
                else
                {
                    Assert.AreEqual(length, e.GetSocketAddress("LocalAddress").Size);
                    Assert.IsTrue(e.TryGetSocketAddress("LocalAddress", out var address));
                    Assert.AreEqual(length, address.Size);
                }
            };
            trace.Enable(provider);
            new Proxy(trace).PushEvent(builder.PackIncomplete());
        }

        [DataTestMethod]
        [DataRow(false)]
        [DataRow(true)]
        public void wrappers_expire_after_normal_and_exceptional_callbacks(bool throws)
        {
            var trace = new UserTrace();
            var provider = new Provider(Events.PowerShellEvent.ProviderId);
            IEventRecordMetadata metadata = null;
            IEventRecord saved = null;
            IEnumerable<Property> properties = null;
            IEnumerator<Property> enumerator = null;
            var expected = new InvalidOperationException("handler");
            provider.OnMetadata += e => metadata = e;
            provider.OnEvent += e =>
            {
                saved = e;
                properties = e.Properties;
                enumerator = properties.GetEnumerator();
                Assert.IsTrue(enumerator.MoveNext());
                if (throws)
                    throw expected;
            };
            trace.Enable(provider);
            var record = Events.PowerShellEvent.CreateRecord("value", "", "");
            var proxy = new Proxy(trace);
            if (throws)
                Assert.AreSame(expected, Assert.ThrowsException<InvalidOperationException>(() => proxy.PushEvent(record)));
            else
                proxy.PushEvent(record);

            Assert.ThrowsException<ObjectDisposedException>(() => { var id = metadata.Id; });
            Assert.ThrowsException<ObjectDisposedException>(() => { var length = saved.UserDataLength; });
            Assert.ThrowsException<ObjectDisposedException>(() => saved.GetUnicodeString(Events.PowerShellEvent.UserData));
            Assert.ThrowsException<ObjectDisposedException>(() => saved.GetStackTrace());
            Assert.ThrowsException<ObjectDisposedException>(() => saved.TryGetContainerId(out _));
            Assert.ThrowsException<ObjectDisposedException>(() => saved.TryGetProcessStartKey(out _));
            Assert.ThrowsException<ObjectDisposedException>(() => properties.GetEnumerator());
            Assert.ThrowsException<ObjectDisposedException>(() => enumerator.MoveNext());
            GC.KeepAlive(record);
        }

        [DataTestMethod]
        [DataRow(false)]
        [DataRow(true)]
        public void error_metadata_expires_but_message_is_durable(bool throws)
        {
            var trace = new UserTrace();
            var provider = new Provider(Events.PowerShellEvent.ProviderId);
            IEventRecordError saved = null;
            var expected = new InvalidOperationException("error handler");
            provider.OnEvent += e => Assert.Fail("Unexpected decoded event");
            provider.OnError += e =>
            {
                saved = e;
                if (throws)
                    throw expected;
            };
            trace.Enable(provider);
            var record = Events.PowerShellEvent.CreateRecord("", "", "");
            record.Id = 1234;
            if (throws)
                Assert.AreSame(expected, Assert.ThrowsException<InvalidOperationException>(
                    () => new Proxy(trace).PushEvent(record)));
            else
                new Proxy(trace).PushEvent(record);
            Assert.IsNotNull(saved.Message);
            Assert.ThrowsException<ObjectDisposedException>(() => { var id = saved.Record.Id; });
            GC.KeepAlive(record);
        }

        [TestMethod]
        public void sized_unicode_preserves_embedded_nul()
        {
            var providerId = new Guid("43D1A55C-76D6-4F7E-995C-64C711E5CAFE");
            var builder = new RecordBuilder(providerId, 404, 0);
            builder.AddValue("TruncatedLength", (ushort)3);
            builder.AddUnicodeString("TruncatedData", "a\0b");
            var trace = new UserTrace();
            var provider = new Provider(providerId);
            var called = false;
            provider.OnEvent += e =>
            {
                called = true;
                Assert.AreEqual("a\0b", e.GetUnicodeString("TruncatedData"));
                Assert.IsTrue(e.TryGetUnicodeString("TruncatedData", out var value));
                Assert.AreEqual("a\0b", value);
            };
            trace.Enable(provider);
            new Proxy(trace).PushEvent(builder.PackIncomplete());
            Assert.IsTrue(called);
        }

        [TestMethod]
        public void zero_length_binary_returns_an_empty_array()
        {
            var providerId = new Guid("43D1A55C-76D6-4F7E-995C-64C711E5CAFE");
            var builder = new RecordBuilder(providerId, 414, 0);
            var trace = new UserTrace();
            var provider = new Provider(providerId);
            var called = false;
            provider.OnEvent += e =>
            {
                called = true;
                CollectionAssert.AreEqual(new byte[0], e.GetBinary("Payload"));
                Assert.IsTrue(e.TryGetBinary("Payload", out var value));
                Assert.AreEqual(0, value.Length);
            };
            trace.Enable(provider);
            new Proxy(trace).PushEvent(builder.PackIncomplete());
            Assert.IsTrue(called);
        }
    }
}
