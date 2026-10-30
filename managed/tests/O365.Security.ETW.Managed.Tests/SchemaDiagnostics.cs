using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace Microsoft.O365.Security.ETW.Tests
{
    /// <summary>
    /// Prints what the schema layer sees for a known event. Kept because a decoding failure
    /// is otherwise invisible: every accessor just returns false.
    /// </summary>
    [Collection("etw")]
    public class SchemaDiagnostics
    {
        private readonly ITestOutputHelper _output;

        public SchemaDiagnostics(ITestOutputHelper output)
        {
            _output = output;
        }

        [Fact]
        public void DumpSchema()
        {
            var lines = new List<string>();
            var signal = new ManualResetEventSlim();

            var filter = new EventFilter(Filter.EventNameIs("Interesting"));
            filter.OnEventRef += (in EventRecordRef record) =>
            {
                if (signal.IsSet)
                {
                    return;
                }

                lines.Add("HasSchema=" + record.HasSchema);
                lines.Add("SchemaStatus=" + record.SchemaStatus);
                lines.Add("Name=" + record.Name.ToString());
                lines.Add("Provider=" + record.ProviderName.ToString());
                lines.Add("DecodingSource=" + record.DecodingSource);
                lines.Add("PropertyCount=" + record.PropertyCount);
                lines.Add("UserDataLength=" + record.UserDataLength);

                for (int i = 0; i < record.PropertyCount; i++)
                {
                    bool ok = record.TryGetRaw(i, out ReadOnlySpan<byte> raw);
                    lines.Add(string.Format(
                        "  [{0}] name='{1}' inType={2} outType={3} raw={4}",
                        i,
                        record.PropertyNameAt(i).ToString(),
                        record.InTypeAt(i),
                        record.OutTypeAt(i),
                        ok ? raw.Length + " bytes" : "FAILED"));
                }

                lines.Add("IndexOf(message)=" + record.IndexOf("message".AsSpan()));
                lines.Add("IndexOf(number)=" + record.IndexOf("number".AsSpan()));

                signal.Set();
            };

            var provider = new Provider(TestTraceLoggingSource.ProviderGuid) { Any = 0 };
            provider.AddFilter(filter);

            using (var trace = new UserTrace("Krabs-Managed-Diag-" + Guid.NewGuid().ToString("N")))
            {
                trace.Enable(provider);
                trace.Open();

                // A dedicated thread rather than the thread pool: ProcessTrace blocks for the
                // whole life of the trace, so a pool thread would be held hostage for 20s.
                var processing = new Thread(() => trace.Start()) { IsBackground = true };
                processing.Start();

                try
                {
                    var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(20);
                    while (DateTime.UtcNow < deadline && !signal.IsSet)
                    {
                        TestTraceLoggingSource.Log.Interesting("diagnostic", 7);
                        signal.Wait(TimeSpan.FromMilliseconds(250), TestContext.Current.CancellationToken);
                    }
                }
                finally
                {
                    trace.Stop();
                    processing.Join(TimeSpan.FromSeconds(20));
                }
            }

            foreach (string line in lines)
            {
                _output.WriteLine(line);
            }

            Assert.True(lines.Count > 0, "No event was captured. LastException=" + (Microsoft.O365.Security.ETW.TraceCallbacks.LastException?.ToString() ?? "none"));
        }
    }
}
