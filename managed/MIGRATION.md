# Migrating to `Microsoft.O365.Security.ETW` 5.0

`Microsoft.O365.Security.ETW` is a pure .NET reimplementation of the C++/CLI wrapper that
shipped as `Microsoft.O365.Security.Native.ETW`, which was itself a thin layer over the
native `krabs` headers.

It ships as a **different package** starting at **5.0.0**. The C++/CLI package continues on
the 4.4.x line, so the two can be installed side by side during migration. The old id retained
"Native" in the name, which no longer describes anything about this implementation.

| | `Microsoft.O365.Security.Native.ETW` | `Microsoft.O365.Security.ETW` |
| --- | --- | --- |
| Package version | 4.4.x | 5.0.0 |
| Assembly | `Microsoft.O365.Security.Native.ETW.dll` | `Microsoft.O365.Security.ETW.dll` |
| Namespace | `Microsoft.O365.Security.ETW` | *unchanged* |
| Target frameworks | net462, net8.0 | net462, net48, net8.0-windows, net10.0-windows |
| Architecture | x64 and ARM64 mixed-mode, under `runtimes/` | one AnyCPU assembly under `lib/` |

Because the namespace is unchanged, most source compiles untouched; replacing the
`PackageReference` is typically the entire migration.

**Nothing is binary-compatible.** The assembly name changes, so every consumer must be
recompiled; anything still bound to the old name will throw `MissingMethodException` or fail
to load. `Assembly.Load` calls and binding redirects naming
`Microsoft.O365.Security.Native.ETW` need updating.

The rest of this document lists every public-surface difference, followed by the two topics
most relevant after the swap: converting a hot handler to allocation-free access, and testing
handlers without a live trace.

---

## Breaking changes

**There are nine.**

| # | Breaking change | Affects |
| --- | --- | --- |
| 1 | `GetDateTime` returns `DateTime`, not a boxed one | implementors of `IEventRecord` |
| 2 | `IDisposable` removed from `Predicate`, `Property`, `KernelProvider`, `RawProvider` | anyone `using`/disposing them |
| 3 | `EventRecord` and `EventRecordMetadata` classes removed | anyone naming the concrete types |
| 4 | `PropertyEnumerable` and `PropertyEnumerator` removed | anyone naming the iterator types |
| 5 | `Property.Type` removed; `Property.OutType` is `uint`, not `int` | readers of `Property` |
| 6 | `EventTraceProperties` fields are now properties | `ref`/`out` use only |
| 7 | `EventHeaderProperty.LEGACY_EVENTLOG` / `FORWARDED_XML` renamed | users of those two members |
| 8 | `IUserTrace.Enable(RawProvider)` removed from the interface | callers via the interface |
| 9 | `Testing.EventHeader` is now `Testing.EventHeaderView` | test code using `RecordBuilder.Header` |

Most consumers encounter none of them. The most likely to apply is #1, and only to code that
implements `IEventRecord` directly.

Separately, five **behaviour** changes compile silently — `TryGet*` on failure, case folding,
`KernelProvider.GroupMask`, `TraceStats` and struct-typed properties. These warrant the
closest reading, and are listed after the nine.

### Compile breaks

**1. `GetDateTime` returns `DateTime` instead of a boxed one.** C++/CLI declared it `DateTime^`,
which surfaces to C# as `System.ValueType`. The port returns `DateTime`, dropping the boxing
allocation.

| Removed | Replaced by |
| --- | --- |
| `IEventRecord.GetDateTime(string) : ValueType` | `GetDateTime(string) : DateTime` |
| `IEventRecord.GetDateTime(string, ValueType) : ValueType` | `GetDateTime(string, DateTime) : DateTime` |
| `IEventRecord.TryGetDateTime(string, out ValueType) : bool` | `TryGetDateTime(string, out DateTime) : bool` |

Implementors of `IEventRecord` break: C# requires an exact signature match to implement an
interface member — there is no return-type covariance — so a class declaring
`public ValueType GetDateTime(string)` no longer implements it. `out` parameters require exact
type identity, so `TryGetDateTime` breaks the same way. **Callers** are largely unaffected;
`ValueType x = record.GetDateTime(…)` still compiles via implicit boxing, and only `var`
inference changes.

The one capability lost is that `null` was a *distinguishable* "no value" sentinel, whereas
`default(DateTime)` is a legal date. `GetUInt32` has always been in the same position — `0`
was never distinguishable either — so this makes `DateTime` consistent rather than an outlier.

**2. `IDisposable` is gone from four types.** `Predicate`, `Property`, `KernelProvider` and
`RawProvider` held a `NativePtr<T>` in C++/CLI, so disposal freed C-runtime heap. The port's
equivalents are plain managed objects with nothing to release, and an empty `Dispose` would
imply an ownership that does not exist. Remove the `using` blocks and `Dispose` calls; a
`using` statement on any of these no longer compiles.

`UserTrace`, `KernelTrace`, `EventFilter`, `Testing.RecordBuilder` and `Testing.SynthRecord`
are unaffected and remain disposable. `Testing.Proxy` *gained* `IDisposable`.

**5. `Property` type members changed.**

| Removed | Replaced by |
| --- | --- |
| `Property.Type : int` | *(nothing — it duplicated `InType`)* |
| `Property.OutType : int` | `Property.OutType : uint` |
| 3-argument `Property` constructor | 4-argument form |
| | `Property.InType : uint` *(new)* |
| | `Property.Length : uint` *(new)* |

**6. `EventTraceProperties` fields became properties.** `BufferSize`, `FlushTimer`,
`LogFileMode`, `MaximumBuffers` and `MinimumBuffers` were public fields and are now
get/set properties. Object-initializer syntax is unaffected — only passing one by `ref` or
`out` breaks.

**7. `EventHeaderProperty` members were renamed** to match .NET naming, and the enum is now
`[Flags]`.

| Removed | Replaced by |
| --- | --- |
| `LEGACY_EVENTLOG` | `LegacyEventLog` |
| `FORWARDED_XML` | `ForwardedXML` |

`None` and `Relogged` are new. `TraceFlags` likewise gained `None` and is now `[Flags]`.

**8. `IUserTrace.Enable(RawProvider)` was removed** from the interface. `RawProvider` is
`[Obsolete]` in both implementations and the replacement is `Provider.OnMetadata`. The
concrete `UserTrace.Enable(RawProvider)` is still there, still obsolete.

**9. `Testing.EventHeader` is now `Testing.EventHeaderView`**, and `RecordBuilder.Header`
returns the new type.

### Types that no longer exist

Items 3 and 4.

| # | Removed | Why |
| --- | --- | --- |
| 3 | `EventRecord`, `EventRecordMetadata` classes | The port's adapter is reused and mutated per event, so naming it publicly makes "hold it past the callback" look supported. C++/CLI also exposed public `_EVENT_HEADER*` / `_EVENT_RECORD*` fields that have no C# equivalent. Keep using `IEventRecord` / `IEventRecordMetadata`, which are unchanged. |
| 4 | `PropertyEnumerable`, `PropertyEnumerator` | Allocated a `Property` per property. `IEventRecord.Properties` still works; only the concrete iterator types are gone. |

`IEventRecordError` *was* kept — `EventRecordError` implements it — because
`EventRecordErrorDelegate` is declared in terms of it and consumers mock it.

### Behaviour changes that still compile

These are the changes that produce no build-time diagnostic.

**`TryGet*` now zeroes the out parameter on failure.** krabs assigns the out parameter only
on success, and `[Out]` in C++/CLI is metadata only — the CLR does not enforce assignment —
so a failed lookup left the caller's variable holding whatever it held before the call. The
port writes the default first.

```csharp
uint v = 42;
if (!record.TryGetUInt32("missing", out v)) { /* C++/CLI: 42    port: 0 */ }
```

This applies to every `TryGet*`. Code that relied on the old behaviour to retain a previous
value changes meaning silently.

**Case-insensitive matching now folds above U+007F.** krabs uses the CRT's `towupper`, and
because nothing ever calls `setlocale` the CRT stays in the `"C"` locale and folds ASCII only.
The port falls back to `char.ToUpperInvariant`. A case-insensitive filter written against a
non-ASCII string will now match where it previously did not. This is intentional — in a
security filter, matching too little means missed detections.

Byte-oriented (ANSI) case folding is ASCII-only in both implementations: folding a single byte
is not well defined without knowing the code page.

**`KernelProvider.GroupMask` is `uint`.** Native `PERFINFO_MASK` is `typedef ULONG`, and
C++/CLI mirrored it as `UInt32`. An intermediate revision of the port widened it to `ulong`
and truncated at the point of use, silently discarding any bit above 32. It is `uint` again,
which makes the invalid value unrepresentable.

**`TraceStats` is a `readonly struct`.** Reading its fields — the only thing consumers do —
is unchanged, as is `new TraceStats()`. Assigning a field on a local no longer compiles, but
the type is only ever produced by `UserTrace.QueryStats` / `KernelTrace.QueryStats`.

**Struct-typed properties are not decoded.** A property carrying `PropertyStruct`, and
everything after it in the payload, is unreadable. krabs does not decode structs either and
fails worse, so nothing that worked before stops working — but the failure mode changes from
silent corruption to a visible failure.

**Not a behaviour change: nullable reference annotations.** The public surface is annotated,
so a project that has opted into nullable reference types now receives accurate diagnostics
where it previously received none. `TryGet*` carries `[MaybeNullWhen(false)]`, which is what
allows `if (record.TryGetUnicodeString(name, out var s))` to narrow `s` to non-null in the
true branch. Annotations are metadata only and cannot break a compile that was not already
opted in.

### New surface

These require no action, but they explain why some call sites can be made faster.

- `EventRecordRef` — the allocation-free record, plus `OnEventRef` / `DefaultEventRef` on
  `Provider`, `EventFilter`, `KernelProvider`, `UserTrace` and `KernelTrace`, and the
  `EventRecordDelegate` they take. See below.
- `Predicate` composition — `&`, `|`, `!`, `Predicate.Not()`, `Predicate.Tier` and the
  `PredicateTier` enum, and `Predicate.Test(in EventRecordRef)`.
- `Filter` additions — `Custom(EventPredicate)`, `NoEvent()`, `EventNameIs`,
  `EventNameIEquals`, `EventLevelIs`, `ProviderIdIs`, `IsUInt64`.
- Properties that were methods or were simply missing — `Provider.Id`/`Name`/`Level`/`Any`/
  `All`/`RundownEnabled`, `UserTrace.Name`/`MOFEventProcessingEnabled`/
  `WPPEventProcessingEnabled`, `KernelTrace.Name`, `KernelProvider.Flags`/`GroupMask`.
- `TraceException` with a `Status`, replacing bare failures.

---

## Converting a handler to zero-allocation comparison

Every getter on `IEventRecord` allocates. That is not an implementation defect — the payload
lives in the ETW buffer, and returning a `string` or a `byte[]` means copying out of it. The
adapter object itself is reused for the life of the trace, so the allocation is entirely in
the return types.

`EventRecordRef` hands back `ReadOnlySpan<T>` views straight into the buffer instead. It is a
`ref struct`, so it can never implement an interface; reaching it means subscribing
`OnEventRef` rather than `OnEvent`.

| | Callback | Record type | Allocates |
| --- | --- | --- | --- |
| Compat | `OnEvent` / `DefaultEvent` | `IEventRecord` | yes |
| Allocation-free | `OnEventRef` / `DefaultEventRef` | `EventRecordRef` | no |

### Where the conversions pay off

A string stored on an object that outlives the callback must be allocated; moving to
`EventRecordRef` cannot avoid it. The conversions worth making are those where a value is
read, **tested, and discarded**:

```csharp
// allocates a string for every event, in order to reject almost all of them
provider.OnEvent += record =>
{
    var user = record.GetUnicodeString("TargetUserName", string.Empty);
    if (!user.StartsWith("svc-", StringComparison.OrdinalIgnoreCase)) return;
    ...
};

// allocates nothing until the event is one of interest
provider.OnEventRef += (in EventRecordRef record) =>
{
    if (!record.TryGetUnicodeString("TargetUserName".AsSpan(), out var user)) return;
    if (!user.StartsWith("svc-".AsSpan(), StringComparison.OrdinalIgnoreCase)) return;
    ...
};
```

The same applies to any guard that precedes the work: emptiness checks, allow-list tests and
prefix/suffix dispatch. Ordering also matters — test `record.Id` and integer properties, which
never allocate, before reading any string.

### Property names are passed as spans

Every accessor on `EventRecordRef` takes the property name as a `ReadOnlySpan<char>`. C# 14
converts a string literal implicitly, so the name can be written bare; **C# 13 and earlier do
not**, and require an explicit `.AsSpan()`:

```csharp
record.TryGetUnicodeString("ImageName".AsSpan(), out var image);  // every language version
record.TryGetUnicodeString("ImageName", out var image);           // C# 14 and later only
```

Omitting `.AsSpan()` on an older compiler produces CS1503 (`cannot convert from 'string' to
'System.ReadOnlySpan<char>'`). The `.AsSpan()` form costs nothing at run time and compiles
everywhere, so it is the form used throughout this document.

### Handlers must declare their parameter explicitly

`EventRecordDelegate` takes `in EventRecordRef`, and a lambda cannot infer a parameter
modifier, so an implicitly typed lambda will not bind:

```csharp
provider.OnEventRef += (in EventRecordRef record) => { ... };   // required
provider.OnEventRef += record => { ... };                       // does not compile
```

A named method may also be subscribed directly, which is generally clearer for a non-trivial
handler: the `in` modifier is declared on the method itself, so the subscription site carries
no modifier at all:

```csharp
provider.OnEventRef += OnProcessStart;

private static void OnProcessStart(in EventRecordRef record)
{
    if (!record.TryGetUnicodeString("ImageName".AsSpan(), out var image)) return;
    if (!image.EndsWith("\\cmd.exe".AsSpan(), StringComparison.OrdinalIgnoreCase)) return;

    Report(record.ProcessId, image.ToString());
}
```

The restriction applies to the *record* only, not to handler state. A handler may capture
`this`, fields and locals as usual, and may pass the record to another method that takes
`in EventRecordRef`. It may not allow the record to outlive the callback: storing it in a
field, capturing it in a nested lambda, or using it after an `await` does not compile.

### Comparing string properties without allocating

Every comparison below allocates nothing, on .NET Framework as well as modern .NET:

```csharp
provider.OnEventRef += (in EventRecordRef record) =>
{
    if (!record.TryGetUnicodeString("ImageName".AsSpan(), out var image)) return;

    // equality
    if (image.Equals("cmd.exe".AsSpan(), StringComparison.OrdinalIgnoreCase)) { }

    // prefix / suffix
    if (image.StartsWith(@"\Device".AsSpan(), StringComparison.Ordinal)) { }
    if (image.EndsWith(".exe".AsSpan(), StringComparison.OrdinalIgnoreCase)) { }

    // substring
    if (image.Contains("system32".AsSpan(), StringComparison.OrdinalIgnoreCase)) { }

    // presence and emptiness guards
    if (image.IsEmpty) return;
    if (image.IsWhiteSpace()) return;

    // a counted string works exactly the same way
    if (record.TryGetCountedString("CommandLine".AsSpan(), out var cmdline)
        && cmdline.Contains("-enc".AsSpan(), StringComparison.OrdinalIgnoreCase))
    {
        // pay for a string only now, and only for the events that were retained
        Report(image.ToString(), cmdline.ToString());
    }
};
```

These are ordinary `MemoryExtensions` methods rather than additions made by this library.
`TryGetUnicodeString` and `TryGetCountedString` return a `ReadOnlySpan<char>`, and the BCL
provides the comparisons. On .NET Framework they are supplied by the `System.Memory` package
the library already references.

**Always pass a `StringComparison` explicitly.** The overloads that omit it are ordinal for
spans, but stating it prevents the call from changing meaning if it is later refactored into a
`string` comparison, where the default is the current culture.

The spans are views into the ETW buffer and are valid **only for the duration of the
callback**, as is the record itself. Retaining a value requires calling `.ToString()` on it,
which incurs the allocation being avoided — so it belongs after the guards, not before.

### What `EventRecordRef` deliberately does not have

A handler that needs any of these stays on `IEventRecord`:

- **`GetAnsiString`.** Transcoding from the provider's ANSI code page is what forces the
  allocation. `TryGetAnsiStringBytes` returns the raw `ReadOnlySpan<byte>` instead. Note there
  is currently no built-in way to compare those bytes against a `string` literal.
- **IP-address and socket-address accessors**, because `IPAddress` and `SocketAddress` are
  classes.
- **`Properties` enumeration.**

---

## Testing handlers

Tests that mock `IEventRecord` keep working. The interface is unchanged in shape, so an
existing `Mock<IEventRecord>` and every `It.IsAny<IEventRecord>()` compile and run against the
port as they did against the C++/CLI assembly.

Tests covering a handler moved to `OnEventRef` do not. `EventRecordRef` is a `ref struct`, and
a mocking framework cannot represent one:

- it cannot be a generic type argument, so `Mock<EventRecordRef>` and
  `It.IsAny<EventRecordRef>()` do not compile;
- it cannot appear in an expression tree, so `Setup` on a member that takes or returns one
  fails (CS8640, CS9244);
- it cannot be boxed, stored in a field, captured in a lambda, or returned from an `async`
  method or iterator.

Construct a real record instead. `Testing.RecordBuilder` lays out a payload and `Testing.Proxy`
pushes it through the same dispatch path a live trace uses, so the handler observes exactly
what it would in production:

```csharp
using (var builder = new RecordBuilder(providerId, id: 7937, version: 1))
{
    builder.AddUnicodeString("UserData", "user");
    builder.AddUnicodeString("ContextInfo", "context");
    builder.AddUnicodeString("Payload", @"C:\Windows\System32\cmd.exe");

    var filter = new EventFilter(Filter.AnyEvent());
    filter.OnEventRef += (in EventRecordRef record) =>
    {
        Assert.True(record.TryGetUnicodeString("Payload".AsSpan(), out ReadOnlySpan<char> payload));
        Assert.True(payload.EndsWith("cmd.exe".AsSpan(), StringComparison.Ordinal));
    };

    using (var proxy = new Proxy(filter))
    using (var record = builder.Pack())
    {
        proxy.PushEvent(record);
    }
}
```

`Proxy` also takes a `UserTrace` or a `KernelTrace` if the code under test wires providers
onto a trace rather than a bare filter.

Four constraints on `RecordBuilder` are easily overlooked:

- **It resolves the layout from a schema, which by default must be registered on the machine.**
  `Pack()` asks TDH for the provider's manifest, so an invented provider GUID fails with
  `CouldNotFindSchema` (status 1168). Either use an in-box provider whose schema is reliably
  present, or declare the schema in the test — see
  [Testing without the provider installed](#testing-without-the-provider-installed).
- **Use `PackIncomplete()` when the schema varies by Windows build.** `Pack()` requires every
  property in the schema to be supplied; events that gained properties in later releases
  otherwise fail with "Not all the properties of the event were filled" on some machines.
- **`AddValue<T>` infers the in-type from the CLR type, and the in-type is validated.** It
  covers the integral and floating-point types plus `Guid`; the in-types that share a CLR
  representation with an integer have dedicated adders — `AddPointer`, `AddFileTime`,
  `AddHexInt32`, `AddHexInt64` — alongside `AddGuid`, `AddBoolean`, `AddSystemTime`, `AddSid`
  and `AddBinary`. Supplying a `ulong` for a property the schema declares as `win:Pointer` is
  rejected with
  `Invalid property type given for property <name> Expected: Pointer Received: UInt64`, so
  check the event's template (`(Get-WinEvent -ListProvider <name>).Events`) when a type is in
  doubt. Counted strings have no adder: use a length-prefixed value in a `UNICODESTRING`
  property (`"\u0008abcd"` reads back as `"abcd"`).
- **A string the schema sizes must match the size the schema is given.** Where a template
  declares `length="ShareNameLength"`, the reader consumes exactly that many characters, so
  the value passed to `AddUnicodeString` and the value passed to the length property have to
  agree. A mismatch is reported by `Pack()` rather than left to decode as truncated text.

Assertions inside a ref handler carry one further constraint: the record cannot be captured,
so `Assert.Throws(() => record.GetUnicodeString("Missing".AsSpan()))` does not compile. Use an
inline `try`/`catch` instead.

To verify that a handler does not allocate, measure inside the callback. This works on .NET
Framework as well as modern .NET, provided the schema and property caches are warmed by an
unmeasured pass first and the value kept alive is not inadvertently boxed:

```csharp
long before = GC.GetAllocatedBytesForCurrentThread();
// ... exercise the accessors ...
Assert.Equal(0, GC.GetAllocatedBytesForCurrentThread() - before);
```

`tests/O365.Security.ETW.Managed.Tests/RefAccessorTests.cs` is a worked example of all of the
above.

### Testing without the provider installed

Both building and reading a record normally require the provider's manifest to be registered
on the machine running the test, because the layout comes from TDH. That is a problem for
providers absent from build agents, for events whose template changed between Windows
releases, and for tests that would rather not depend on a real provider at all.

A test may instead declare the schema. While the declaration is in scope it answers for the
events it describes, and nothing downstream can tell the difference — `RecordBuilder`
validates and lays out against it, and the accessors resolve reads from it:

```csharp
static readonly Guid ProviderId = Guid.Parse("6f2b1d64-1f4e-4d0a-9f1c-2b7e9a3c5d81");

static EventSchema FileOpened() => EventSchema
    .Create("Contoso-Test-Provider", ProviderId, id: 42, version: 1)
    .Named("FileOpened")
    .UInt32("ProcessId")
    .Pointer("Handle")
    .UInt16("PathLength")
    .UnicodeString("Path", lengthFrom: "PathLength")
    .UnicodeString("Comment");

[Fact]
public void ReadsThePath()
{
    using var declaration = EventSchema.Use(FileOpened());
    using var builder = new RecordBuilder(ProviderId, id: 42, version: 1);

    builder.AddValue("ProcessId", 4321u);
    builder.AddPointer("Handle", 0xFFFFAB0012345678);
    builder.AddValue("PathLength", (ushort)@"C:\Windows\notepad.exe".Length);
    builder.AddUnicodeString("Path", @"C:\Windows\notepad.exe");
    builder.AddUnicodeString("Comment", "opened for read");

    // ... push through a Proxy and assert as usual ...
}
```

There is a fluent method per in-type — `UInt32`, `Pointer`, `Guid`, `FileTime`, `Sid`,
`Binary` and the rest — and `lengthFrom` declares a string or binary property sized by an
earlier one, as `length="PathLength"` does in a manifest. `Named` supplies the value
`EventRecordRef.Name` reports; the provider name passed to `Create` supplies `ProviderName`.

Two points are worth keeping in mind:

- **A declaration is only as accurate as whoever wrote it.** It records what the test believes
  the event looks like, so a declaration that has drifted from the real manifest yields a
  passing test against an event shape that is never emitted. Prefer a real in-box provider
  where one exists, and keep the declaration next to the template it mirrors.
- **The scope is the execution context, not the process.** Tests running in parallel do not
  see one another's declarations, and disposing the value returned by `Use` restores whatever
  was in scope before. Declarations do not reach a live trace's processing thread, which needs
  none: events delivered by ETW come from providers that are registered by definition.

### Converting a producer test

The example above asserts inside the handler, which suits a handler defined inline. Production
handlers are more often private methods on a producer class that raises a domain event, and
their tests reach the handler by reflection while substituting a hand-written `IEventRecord`:

```csharp
// before: a fake record, and reflection to reach a private handler
var record = new FakeEventRecord { Id = 1 };
record.Data["ProcessID"] = 4321u;
record.Data["ImageName"] = @"\Device\HarddiskVolume4\Windows\System32\cmd.exe";

producer.GetType()
    .GetMethod("OnProcessStart", BindingFlags.NonPublic | BindingFlags.Instance)
    .Invoke(producer, new object[] { record });

Assert.Equal("cmd.exe", produced.Single().ImageName);
```

Neither half of that survives the move to `OnEventRef`. The fake is an `IEventRecord`
implementation, which `EventRecordRef` is not, and the reflection call cannot be repaired:
`new object[] { record }` fails to compile with CS0029, because a `ref struct` cannot be boxed.
`MethodInfo.Invoke` passes arguments as `object`, so no amount of reflection can deliver one.

Build the record and let the producer's own filter dispatch it. The producer needs to expose
the filter — or the trace it registers on — so a test can hand it to `Proxy`:

```csharp
using static Microsoft.O365.Security.ETW.Filter;

public sealed class ProcessStarted
{
    public DateTime TimeStamp { get; set; }
    public uint ProcessId { get; set; }
    public string ImageName { get; set; }
}

public sealed class ProcessStartProducer
{
    private readonly string[] _ignoredImages;

    public event Action<ProcessStarted> OnDataProduced;

    public EventFilter Filter { get; }

    public ProcessStartProducer(params string[] ignoredImages)
    {
        _ignoredImages = ignoredImages;

        Filter = new EventFilter(EventIdIs(1));
        Filter.OnEventRef += OnProcessStart;
    }

    private void OnProcessStart(in EventRecordRef record)
    {
        if (!record.TryGetUnicodeString("ImageName".AsSpan(), out var imagePath)) return;

        // \Device\HarddiskVolume4\Windows\System32\cmd.exe -> cmd.exe
        var image = imagePath.Slice(imagePath.LastIndexOf('\\') + 1);

        foreach (var ignored in _ignoredImages)
        {
            if (image.Equals(ignored.AsSpan(), StringComparison.OrdinalIgnoreCase)) return;
        }

        // The started process is named by the payload. The header's ProcessId is the
        // process that created it.
        if (!record.TryGetUInt32("ProcessID".AsSpan(), out uint processId)) return;

        OnDataProduced?.Invoke(new ProcessStarted
        {
            TimeStamp = record.Timestamp,
            ProcessId = processId,
            ImageName = image.ToString(),
        });
    }
}
```

The test then subscribes to the domain event and pushes a record through the producer, with no
reflection and no fake record type:

```csharp
private static readonly Guid KernelProcess = new Guid("22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716");

[Fact]
public void EmitsAnEventWhenAProcessStarts()
{
    var produced = new List<ProcessStarted>();

    var producer = new ProcessStartProducer("conhost.exe");
    producer.OnDataProduced += e => produced.Add(e);

    using (var proxy = new Proxy(producer.Filter))
    using (var record = Build(4321, @"\Device\HarddiskVolume4\Windows\System32\cmd.exe"))
    {
        proxy.PushEvent(record);
    }

    Assert.Equal(1, produced.Count);
    Assert.Equal("cmd.exe", produced[0].ImageName);
    Assert.Equal(4321u, produced[0].ProcessId);
}

private static SynthRecord Build(uint processId, string imageName)
{
    using (var builder = new RecordBuilder(KernelProcess, id: 1, version: 1))
    {
        builder.AddValue("ProcessID", processId);
        builder.AddFileTime("CreateTime", DateTime.UtcNow);
        builder.AddValue("ParentProcessID", 4u);
        builder.AddValue("SessionID", 0u);
        builder.AddValue("Flags", 0u);
        builder.AddUnicodeString("ImageName", imageName);

        return builder.Pack();
    }
}
```

Two properties of this conversion are worth noting.

The fake record disappears entirely. A hand-written `IEventRecord` is a substantial fixture —
every accessor, backed by a dictionary — and one that answers from a dictionary rather than
from a payload, so it cannot reproduce a decoding failure, a missing property in a particular
schema version, or a length that disagrees with its declared type. `RecordBuilder` lays out
real bytes and TDH decodes them.

Coverage also increases. Invoking the handler by reflection bypasses the `EventFilter`, so the
event ID and every predicate were never exercised; a test could assert an event that the
production pipeline would in fact reject before the handler ran. Pushing through `Proxy` runs
the same predicate chain a live trace runs, which makes the negative cases meaningful:

```csharp
// filtered out by the handler
proxy.PushEvent(Build(4321, @"\Device\HarddiskVolume4\Windows\System32\conhost.exe"));

// rejected by the filter before the handler runs: ProcessStop, not ProcessStart.
// PackIncomplete builds a record for the rejected path without restating the template.
using (var stop = new RecordBuilder(KernelProcess, id: 2, version: 1))
{
    proxy.PushEvent(stop.PackIncomplete());
}

Assert.Empty(produced);
```

The same harness pins the allocation behaviour, because the rejected path is the one that
matters — it runs for every event:

```csharp
using (var record = Build(4321, @"\Device\HarddiskVolume4\Windows\System32\conhost.exe"))
{
    for (int i = 0; i < 200; i++) proxy.PushEvent(record);   // warm the schema and property caches

    long before = GC.GetAllocatedBytesForCurrentThread();
    for (int i = 0; i < 1000; i++) proxy.PushEvent(record);

    Assert.Equal(0, GC.GetAllocatedBytesForCurrentThread() - before);
}
```

---

`PARITY.md` covers the engineering side of the same ground: how the two implementations were
differenced, where they agree in a way that looks wrong, and defects still open on one side
or both.
