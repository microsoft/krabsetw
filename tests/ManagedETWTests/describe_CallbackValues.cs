// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.O365.Security.ETW;
using Microsoft.O365.Security.ETW.Testing;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace EtwTestsCS
{
    [TestClass]
    public class describe_CallbackValues
    {
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

        private static readonly Guid Utf8Provider = Guid.NewGuid();
        private static string utf8ManifestPath;

        [DllImport("tdh.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        private static extern uint TdhLoadManifest(string manifest);

        [DllImport("tdh.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        private static extern uint TdhUnloadManifest(string manifest);

        [ClassInitialize]
        public static void LoadUtf8Schema(TestContext context)
        {
            // Load only into this process; do not require or register a machine-wide provider.
            utf8ManifestPath = Path.Combine(Path.GetTempPath(), Utf8Provider.ToString("N") + ".man");
            File.WriteAllText(utf8ManifestPath, $@"<instrumentationManifest
    xmlns=""http://schemas.microsoft.com/win/2004/08/events""
    xmlns:win=""http://manifests.microsoft.com/win/2004/08/windows/events"">
  <instrumentation>
    <events>
      <provider name=""Krabs-Tests-Utf8"" guid=""{Utf8Provider:B}"" symbol=""KrabsTestsUtf8""
          resourceFileName=""unused.dll"" messageFileName=""unused.dll"">
        <events>
          <event value=""10003"" version=""0"" template=""Utf8"" />
          <event value=""10004"" version=""0"" template=""MixedEncoding"" />
          <event value=""10005"" version=""0"" template=""SizedUtf8"" />
        </events>
        <templates>
          <template tid=""Utf8"">
            <data name=""ExceptionWhatString"" inType=""win:AnsiString"" outType=""win:Utf8"" />
          </template>
          <template tid=""MixedEncoding"">
            <data name=""AnsiValue"" inType=""win:AnsiString"" />
            <data name=""Utf8Value"" inType=""win:AnsiString"" outType=""win:Utf8"" />
            <data name=""JsonValue"" inType=""win:AnsiString"" outType=""win:Json"" />
          </template>
          <template tid=""SizedUtf8"">
            <data name=""Size"" inType=""win:UInt16"" />
            <data name=""Value"" inType=""win:AnsiString"" outType=""win:Utf8"" length=""Size"" />
          </template>
        </templates>
      </provider>
    </events>
  </instrumentation>
</instrumentationManifest>");
            Assert.AreEqual(0U, TdhLoadManifest(utf8ManifestPath), "Could not load the UTF-8 test manifest.");
        }

        [ClassCleanup]
        public static void UnloadUtf8Schema()
        {
            if (utf8ManifestPath == null)
                return;
            try
            {
                Assert.AreEqual(0U, TdhUnloadManifest(utf8ManifestPath), "Could not unload the UTF-8 test manifest.");
            }
            finally
            {
                File.Delete(utf8ManifestPath);
            }
        }

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

        [DataTestMethod]
        [DataRow("AnsiValue", false)]
        [DataRow("Utf8Value", true)]
        [DataRow("JsonValue", true)]
        public void ansi_encoding_uses_the_resolved_property(string name, bool utf8)
        {
            var builder = new RecordBuilder(Utf8Provider, 10004, 0);
            builder.AddAnsiString("AnsiValue", "xx");
            builder.AddAnsiString("Utf8Value", "xx");
            builder.AddAnsiString("JsonValue", "xx");
            var record = builder.Pack();
            var trace = new UserTrace();
            var provider = new Provider(Utf8Provider);
            string expectedAnsi = null;
            bool called = false;
            provider.OnMetadata += e =>
            {
                Marshal.Copy(new byte[] { 0xC3, 0xA9, 0, 0xC3, 0xA9, 0, 0xC3, 0xA9, 0 },
                    0, e.UserData, 9);
                expectedAnsi = Marshal.PtrToStringAnsi(e.UserData, 2);
            };
            provider.OnEvent += e =>
            {
                called = true;
                Assert.AreEqual("\u00e9", e.GetAnsiString("JsonValue"));
                Assert.IsTrue(e.TryGetAnsiString("AnsiValue", out var ansi));
                Assert.AreEqual(expectedAnsi, ansi);
                Assert.AreEqual("\u00e9", e.GetAnsiString("Utf8Value"));
                Assert.IsTrue(e.TryGetAnsiString("JsonValue", out var json));
                Assert.AreEqual("\u00e9", json);
                Assert.IsFalse(e.TryGetAnsiString("Missing", out _));
                Assert.AreEqual(expectedAnsi, e.GetAnsiString("AnsiValue"));
            };
            trace.Enable(provider);
            new Proxy(trace).PushEvent(record);
            Assert.IsTrue(called);
            string expected = utf8 ? "\u00e9" : expectedAnsi;
            Assert.IsTrue(AnsiString.Is(name, expected).Test(record));
            Assert.IsTrue(AnsiString.Contains(name, expected).Test(record));
            Assert.IsTrue(AnsiString.StartsWith(name, expected).Test(record));
            Assert.IsTrue(AnsiString.EndsWith(name, expected).Test(record));
            Assert.IsTrue(AnsiString.IEquals(name, expected).Test(record));
            Assert.IsTrue(AnsiString.IContains(name, expected).Test(record));
            Assert.IsTrue(AnsiString.IStartsWith(name, expected).Test(record));
            Assert.IsTrue(AnsiString.IEndsWith(name, expected).Test(record));
            Assert.IsFalse(AnsiString.Is(name, "wrong").Test(record));
            Assert.IsFalse(AnsiString.Is("Missing", expected).Test(record));
        }

        [DataTestMethod]
        [DataRow(0)]
        [DataRow(128)]
        [DataRow(4096)]
        public void utf8_decoding_preserves_bounded_output(int prefixLength)
        {
            string expected = prefixLength == 0 ? "" :
                new string('x', prefixLength) + "\u00e9\ud83d\ude80\0tail";
            byte[] bytes = System.Text.Encoding.UTF8.GetBytes(expected);
            var builder = new RecordBuilder(Utf8Provider, 10005, 0);
            builder.AddValue("Size", (ushort)bytes.Length);
            builder.AddAnsiString("Value", new string('x', bytes.Length));
            var trace = new UserTrace();
            var provider = new Provider(Utf8Provider);
            bool called = false;
            provider.OnMetadata += e => Marshal.Copy(bytes, 0, IntPtr.Add(e.UserData, 2), bytes.Length);
            provider.OnEvent += e =>
            {
                called = true;
                Assert.AreEqual(expected, e.GetAnsiString("Value"));
                Assert.IsTrue(e.TryGetAnsiString("Value", out var value));
                Assert.AreEqual(expected, value);
            };
            trace.Enable(provider);
            new Proxy(trace).PushEvent(builder.Pack());
            Assert.IsTrue(called);
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
