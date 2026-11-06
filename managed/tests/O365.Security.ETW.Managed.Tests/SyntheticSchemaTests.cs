using System;
using Microsoft.O365.Security.ETW;
using Microsoft.O365.Security.ETW.Testing;
using Xunit;

namespace Microsoft.O365.Security.ETW.Tests
{
    /// <summary>
    /// Covers declared schemas, which let a test build and read a record for a provider that
    /// is not registered on the machine running the test.
    /// </summary>
    public class SyntheticSchemaTests
    {
        /// <summary>
        /// Deliberately not a real provider. Without a declaration, TDH cannot resolve it.
        /// </summary>
        private static readonly Guid AbsentProviderId = Guid.Parse("6f2b1d64-1f4e-4d0a-9f1c-2b7e9a3c5d81");

        private delegate void RefAssert(in EventRecordRef record);

        private static EventSchema Declaration()
        {
            return EventSchema
                .Create("Contoso-Test-Provider", AbsentProviderId, id: 42, version: 1)
                .Named("FileOpened")
                .UInt32("ProcessId")
                .Pointer("Handle")
                .Guid("ActivityId")
                .UInt16("PathLength")
                .UnicodeString("Path", lengthFrom: "PathLength")
                .UnicodeString("Comment");
        }

        [Fact]
        public void ADeclaredSchemaBuildsAndReadsWithoutTheProviderInstalled()
        {
            using (EventSchema.Use(Declaration()))
            {
                WithRecord((in EventRecordRef record) =>
                {
                    Assert.True(record.TryGetUInt32("ProcessId".AsSpan(), out uint pid));
                    Assert.Equal(4321u, pid);

                    Assert.True(record.TryGetPointer("Handle".AsSpan(), out ulong handle));
                    Assert.Equal(0xFFFFAB0012345678, handle);

                    Assert.True(record.TryGetUnicodeString("Path".AsSpan(), out ReadOnlySpan<char> path));
                    Assert.Equal(@"C:\Windows\notepad.exe", path.ToString());

                    Assert.True(record.TryGetUnicodeString("Comment".AsSpan(), out ReadOnlySpan<char> comment));
                    Assert.Equal("opened for read", comment.ToString());
                });
            }
        }

        [Fact]
        public void ADeclaredSchemaSuppliesTheEventAndProviderNames()
        {
            using (EventSchema.Use(Declaration()))
            {
                WithRecord((in EventRecordRef record) =>
                {
                    Assert.Equal("FileOpened", record.Name.ToString());
                    Assert.Equal("Contoso-Test-Provider", record.ProviderName.ToString());
                    Assert.Equal(6, record.PropertyCount);
                });
            }
        }

        [Fact]
        public void ADeclarationOnlyAppliesWithinItsScope()
        {
            using (EventSchema.Use(Declaration()))
            {
                using (var builder = new RecordBuilder(AbsentProviderId, id: 42, version: 1))
                {
                    builder.AddValue("ProcessId", 1u);
                    builder.PackIncomplete();
                }
            }

            using (var builder = new RecordBuilder(AbsentProviderId, id: 42, version: 1))
            {
                builder.AddValue("ProcessId", 1u);
                Assert.Throws<CouldNotFindSchema>(() => builder.PackIncomplete());
            }
        }

        [Fact]
        public void ADeclarationIsMatchedOnVersion()
        {
            using (EventSchema.Use(Declaration()))
            {
                using (var builder = new RecordBuilder(AbsentProviderId, id: 42, version: 2))
                {
                    builder.AddValue("ProcessId", 1u);
                    Assert.Throws<CouldNotFindSchema>(() => builder.PackIncomplete());
                }
            }
        }

        [Fact]
        public void ADeclaredSchemaStillValidatesInTypes()
        {
            using (EventSchema.Use(Declaration()))
            {
                using (var builder = new RecordBuilder(AbsentProviderId, id: 42, version: 1))
                {
                    builder.AddValue("Handle", 1ul);

                    var error = Assert.Throws<ArgumentException>(() => builder.PackIncomplete());
                    Assert.Contains("Expected: Pointer", error.Message);
                }
            }
        }

        [Fact]
        public void SeveralDeclarationsCanBeInScopeAtOnce()
        {
            var other = EventSchema
                .Create("Contoso-Test-Provider", AbsentProviderId, id: 43, version: 0)
                .UInt64("Bytes");

            using (EventSchema.Use(Declaration(), other))
            {
                using (var builder = new RecordBuilder(AbsentProviderId, id: 43, version: 0))
                {
                    builder.AddValue("Bytes", 900ul);

                    var filter = new EventFilter(Filter.AnyEvent());
                    ulong seen = 0;
                    filter.OnEventRef += (in EventRecordRef record) =>
                    {
                        record.TryGetUInt64("Bytes".AsSpan(), out seen);
                    };

                    new Proxy(filter).PushEvent(builder.Pack());
                    Assert.Equal(900ul, seen);
                }
            }
        }

        private static void WithRecord(RefAssert refAssert)
        {
            using (var builder = new RecordBuilder(AbsentProviderId, id: 42, version: 1))
            {
                builder.AddValue("ProcessId", 4321u);
                builder.AddPointer("Handle", 0xFFFFAB0012345678);
                builder.AddGuid("ActivityId", Guid.NewGuid());
                builder.AddValue("PathLength", (ushort)@"C:\Windows\notepad.exe".Length);
                builder.AddUnicodeString("Path", @"C:\Windows\notepad.exe");
                builder.AddUnicodeString("Comment", "opened for read");

                var filter = new EventFilter(Filter.AnyEvent());
                Exception failure = null;
                int seen = 0;

                filter.OnEventRef += (in EventRecordRef record) =>
                {
                    seen++;
                    try
                    {
                        refAssert(record);
                    }
                    catch (Exception e)
                    {
                        failure = e;
                    }
                };

                new Proxy(filter).PushEvent(builder.Pack());

                Assert.Equal(1, seen);
                if (failure != null)
                {
                    throw failure;
                }
            }
        }
    }
}
