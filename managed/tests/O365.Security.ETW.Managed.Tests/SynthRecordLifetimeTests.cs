using System;
using Microsoft.O365.Security.ETW;
using Microsoft.O365.Security.ETW.Testing;
using Xunit;

namespace Microsoft.O365.Security.ETW.Tests
{
    /// <summary>
    /// A synthetic record's payload lives in unmanaged memory that a finalizer releases, so
    /// the record has to stay reachable for as long as anything is reading through the raw
    /// pointer taken from it.
    /// </summary>
    /// <remarks>
    /// <c>proxy.PushEvent(builder.Pack())</c> is the shape every example uses, and it leaves
    /// the record referenced only by the argument. Once the pointer has been read the JIT is
    /// free to treat the record as dead, so a collection during dispatch can finalize it and
    /// leave the handler reading freed memory -- an access violation that takes the process
    /// with it, and one that only appears when a collection happens to land inside the
    /// callback.
    /// </remarks>
    public class SynthRecordLifetimeTests
    {
        private static readonly Guid PowerShellProviderId = Guid.Parse("A0C1853B-5C40-4B15-8766-3CF1C58F985A");

        [Fact]
        public void ARecordSurvivesACollectionInsideTheRefHandler()
        {
            var filter = new EventFilter(Filter.AnyEvent());
            string payload = null;

            filter.OnEventRef += (in EventRecordRef record) =>
            {
                Collect();

                record.TryGetUnicodeString("Payload".AsSpan(), out ReadOnlySpan<char> value);
                payload = value.ToString();
            };

            using (var proxy = new Proxy(filter))
            {
                proxy.PushEvent(Record());
            }

            Assert.Equal("payload", payload);
        }

        [Fact]
        public void ARecordSurvivesACollectionInsideTheCompatHandler()
        {
            var filter = new EventFilter(Filter.AnyEvent());
            string payload = null;

            filter.OnEvent += record =>
            {
                Collect();
                payload = record.GetUnicodeString("Payload");
            };

            using (var proxy = new Proxy(filter))
            {
                proxy.PushEvent(Record());
            }

            Assert.Equal("payload", payload);
        }

        [Fact]
        public void ARecordSurvivesACollectionInsideAPredicate()
        {
            var predicate = new CollectingPredicate();

            Assert.True(predicate.Test(Record()));
        }

        private sealed class CollectingPredicate : Predicate
        {
            public override bool Test(in EventRecordRef record)
            {
                Collect();

                return record.TryGetUnicodeString("Payload".AsSpan(), out ReadOnlySpan<char> value)
                    && value.SequenceEqual("payload".AsSpan());
            }
        }

        private static SynthRecord Record()
        {
            using (var builder = new RecordBuilder(PowerShellProviderId, 7937, 1))
            {
                builder.AddUnicodeString("UserData", "user data");
                builder.AddUnicodeString("ContextInfo", "context info");
                builder.AddUnicodeString("Payload", "payload");

                return builder.Pack();
            }
        }

        private static void Collect()
        {
            GC.Collect();
            GC.WaitForPendingFinalizers();
            GC.Collect();
        }
    }
}
