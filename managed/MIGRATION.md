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
    if (!record.TryGetUnicodeString("TargetUserName", out var user)) return;
    if (!user.StartsWith("svc-".AsSpan(), StringComparison.OrdinalIgnoreCase)) return;
    ...
};
```

The same applies to any guard that precedes the work: emptiness checks, allow-list tests and
prefix/suffix dispatch. Ordering also matters — test `record.Id` and integer properties, which
never allocate, before reading any string.

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
    if (!record.TryGetUnicodeString("ImageName", out var image)) return;
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
    if (!record.TryGetUnicodeString("ImageName", out var image)) return;

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
    if (record.TryGetCountedString("CommandLine", out var cmdline)
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
        Assert.True(record.TryGetUnicodeString("Payload", out ReadOnlySpan<char> payload));
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

Three constraints on `RecordBuilder` are easily overlooked:

- **It requires a real, registered TDH schema.** `Pack()` resolves the layout from the
  provider's manifest on the machine running the test, so an invented provider GUID fails with
  `CouldNotFindSchema` (status 1168). Use an in-box provider whose schema is reliably present.
- **Use `PackIncomplete()` when the schema varies by Windows build.** `Pack()` requires every
  property in the schema to be supplied; events that gained properties in later releases
  otherwise fail with "Not all the properties of the event were filled" on some machines.
- **There is no adder for binary or counted-string properties.** `AddValue<T>` covers the
  integral types. A counted string is a length-prefixed value in a `UNICODESTRING` property
  (`"\u0008abcd"` reads back as `"abcd"`), and `TryGetBinary` works against any property.

Assertions inside a ref handler carry one further constraint: the record cannot be captured,
so `Assert.Throws(() => record.GetUnicodeString("Missing"))` does not compile. Use an inline
`try`/`catch` instead.

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

---

`PARITY.md` covers the engineering side of the same ground: how the two implementations were
differenced, where they agree in a way that looks wrong, and defects still open on one side
or both.
