# Migrating to `Microsoft.O365.Security.ETW` 5.0

`Microsoft.O365.Security.ETW` is a pure .NET reimplementation of the C++/CLI wrapper that
shipped as `Microsoft.O365.Security.Native.ETW`, which was itself a thin layer over the
native `krabs` headers.

It ships as a **different package** starting at **5.0.0**. The C++/CLI package continues on
the 4.4.x line, so the two can be installed side by side while you migrate. The old id kept
"Native" in the name, which no longer describes anything about this implementation.

| | `Microsoft.O365.Security.Native.ETW` | `Microsoft.O365.Security.ETW` |
| --- | --- | --- |
| Package version | 4.4.x | 5.0.0 |
| Assembly | `Microsoft.O365.Security.Native.ETW.dll` | `Microsoft.O365.Security.ETW.dll` |
| Namespace | `Microsoft.O365.Security.ETW` | *unchanged* |
| Target frameworks | net462, net8.0 | net462, net48, net8.0-windows, net10.0-windows |
| Architecture | x64 and ARM64 mixed-mode, under `runtimes/` | one AnyCPU assembly under `lib/` |

Because the namespace is unchanged, most source compiles untouched — swapping the
`PackageReference` is usually the whole migration.

**Nothing is binary-compatible.** The assembly name changes, so every consumer must be
recompiled; anything still bound to the old name will throw `MissingMethodException` or fail
to load. `Assembly.Load` calls and binding redirects naming
`Microsoft.O365.Security.Native.ETW` need updating.

The rest of this document lists every public-surface difference, then covers the two things
you are most likely to want after the swap: moving a hot handler off allocation, and testing
handlers without a live trace.

---

## Breaking changes

Every difference between the C++/CLI public surface and the port is listed here. They are
grouped by what you have to do about them.

### Compile breaks

**`GetDateTime` returns `DateTime` instead of a boxed one.** C++/CLI declared it `DateTime^`,
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
type identity, so `TryGetDateTime` breaks the same way. **Callers** are mostly fine;
`ValueType x = record.GetDateTime(…)` still compiles via implicit boxing, and only `var`
inference shifts.

The one capability genuinely lost is that `null` was a *distinguishable* "no value" sentinel,
where `default(DateTime)` is a legal date. `GetUInt32` has always been in that position — `0`
was never distinguishable either — so this makes `DateTime` consistent rather than an outlier.

**`IDisposable` is gone from four types.** `Predicate`, `Property`, `KernelProvider` and
`RawProvider` held a `NativePtr<T>` in C++/CLI, so disposal freed C-runtime heap. The port's
equivalents are plain managed objects with nothing to release, and an empty `Dispose` would
imply an ownership that does not exist. Remove the `using` blocks and `Dispose` calls; a
`using` statement on any of these no longer compiles.

`UserTrace`, `KernelTrace`, `EventFilter`, `Testing.RecordBuilder` and `Testing.SynthRecord`
remain disposable. `Testing.Proxy` gained `IDisposable`.

**`Property` type members changed.**

| Removed | Replaced by |
| --- | --- |
| `Property.Type : int` | *(nothing — it duplicated `InType`)* |
| `Property.OutType : int` | `Property.OutType : uint` |
| 3-argument `Property` constructor | 4-argument form |
| | `Property.InType : uint` *(new)* |
| | `Property.Length : uint` *(new)* |

**`EventTraceProperties` fields became properties.** `BufferSize`, `FlushTimer`,
`LogFileMode`, `MaximumBuffers` and `MinimumBuffers` were public fields and are now
get/set properties. Object-initializer syntax is unaffected — only passing one by `ref` or
`out` breaks.

**`EventHeaderProperty` members were renamed** to match .NET naming, and the enum is now
`[Flags]`.

| Removed | Replaced by |
| --- | --- |
| `LEGACY_EVENTLOG` | `LegacyEventLog` |
| `FORWARDED_XML` | `ForwardedXML` |

`None` and `Relogged` are new. `TraceFlags` likewise gained `None` and is now `[Flags]`.

**`IUserTrace.Enable(RawProvider)` was removed** from the interface. `RawProvider` is
`[Obsolete]` in both implementations and the replacement is `Provider.OnMetadata`. The
concrete `UserTrace.Enable(RawProvider)` is still there, still obsolete.

**`Testing.EventHeader` is now `Testing.EventHeaderView`**, and `RecordBuilder.Header`
returns the new type.

### Types that no longer exist

| Removed | Why |
| --- | --- |
| `EventRecord`, `EventRecordMetadata` classes | The port's adapter is reused and mutated per event, so naming it publicly makes "hold it past the callback" look supported. C++/CLI also exposed public `_EVENT_HEADER*` / `_EVENT_RECORD*` fields that have no C# equivalent. Keep using `IEventRecord` / `IEventRecordMetadata`, which are unchanged. |
| `PropertyEnumerable`, `PropertyEnumerator` | Allocated a `Property` per property. `IEventRecord.Properties` still works; only the concrete iterator types are gone. |

`IEventRecordError` *was* kept — `EventRecordError` implements it — because
`EventRecordErrorDelegate` is declared in terms of it and consumers mock it.

### Behaviour changes that still compile

These are the dangerous ones: nothing tells you at build time.

**`TryGet*` now zeroes the out parameter on failure.** krabs assigns the out parameter only
on success, and `[Out]` in C++/CLI is metadata only — the CLR does not enforce assignment —
so a failed lookup left your variable holding whatever it held before the call. The port
writes the default first.

```csharp
uint v = 42;
if (!record.TryGetUInt32("missing", out v)) { /* C++/CLI: 42    port: 0 */ }
```

This applies to every `TryGet*`. If you relied on the old behaviour to keep a previous value,
that code silently changes meaning.

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

**Nullable reference annotations are present.** The public surface is annotated, so if you
have opted into nullable reference types you will get accurate diagnostics where you
previously got none. `TryGet*` carries `[MaybeNullWhen(false)]`, which is what lets
`if (record.TryGetUnicodeString(name, out var s))` narrow `s` to non-null in the true branch.
Annotations are metadata only and cannot break a compile that was not already opted in.

### New surface

You do not have to do anything about these, but they are why some call sites can get faster.

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

### Differences that need no action

For completeness, the remaining entries in the surface diff are mechanical and cannot affect
consuming code:

- **Finalizers and `Dispose(bool)`.** C++/CLI generated `~Type()` and a protected
  `Dispose(bool)` for every disposable type. The port's disposable types are sealed and hold
  no unmanaged resource that outlives them, so neither member exists. Both are non-public or
  non-callable, and the `Dispose()` you call is unchanged.
- **Compiler-generated delegate members.** `BeginInvoke`, `EndInvoke` and `Invoke` on the
  delegate types, which the port does not emit for the new delegates.
- **Enum `value__` fields and implicit constructors**, which are artefacts of how each
  compiler emits types.

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

### Where the wins actually are

A string that is stored on an object outliving the callback has to be allocated — moving to
`EventRecordRef` cannot help it. The conversions worth doing are the ones where a value is
read, **tested, and discarded**:

```csharp
// allocates a string for every event, to reject almost all of them
provider.OnEvent += record =>
{
    var user = record.GetUnicodeString("TargetUserName", string.Empty);
    if (!user.StartsWith("svc-", StringComparison.OrdinalIgnoreCase)) return;
    ...
};

// allocates nothing until the event is one you want
provider.OnEventRef += (in EventRecordRef record) =>
{
    if (!record.TryGetUnicodeString("TargetUserName", out var user)) return;
    if (!user.StartsWith("svc-".AsSpan(), StringComparison.OrdinalIgnoreCase)) return;
    ...
};
```

The same applies to any guard that runs before the work: emptiness checks, allow-list tests,
prefix/suffix dispatch. Reordering helps too — test `record.Id` and integer properties, which
never allocate, before reading any string.

### Handlers must declare their parameter explicitly

`EventRecordDelegate` takes `in EventRecordRef`, and a lambda cannot infer a parameter
modifier, so an implicitly typed lambda will not bind:

```csharp
provider.OnEventRef += (in EventRecordRef record) => { ... };   // required
provider.OnEventRef += record => { ... };                       // does not compile
```

A method group works too, and is usually tidier for a real handler.

### Comparing spans

`ReadOnlySpan<char>` comparison needs nothing from this library. `Equals`, `StartsWith`,
`EndsWith` and `Contains` all take a `StringComparison`, and `IsEmpty` / `IsWhiteSpace()`
cover the guards — all allocation-free, including `OrdinalIgnoreCase`, and all available on
.NET Framework through the `System.Memory` package the library already brings in.

`TryGetUnicodeString` and `TryGetCountedString` hand you a `ReadOnlySpan<char>` directly, so
those properties need no further help.

The spans are views into the ETW buffer and are valid **only for the duration of the
callback**, exactly like the record itself. To keep a value, call `.ToString()` on it —
which is the allocation you were avoiding, so do it after the guards, not before.

### What `EventRecordRef` deliberately does not have

A handler that needs any of these stays on `IEventRecord`:

- **`GetAnsiString`.** Transcoding from the provider's ANSI code page is what forces the
  allocation. `TryGetAnsiStringBytes` returns the raw `ReadOnlySpan<byte>` instead. Note there
  is currently no built-in way to compare those bytes against a `string` literal.
- **IP-address and socket-address accessors**, because `IPAddress` and `SocketAddress` are
  classes.
- **`Properties` enumeration.**

### Why there are no span accessors on `IEventRecord`

An earlier revision added six span-returning members to `IEventRecord` so a consumer could
migrate one call site at a time. They were removed before release.

Overloading on the *name* parameter meant
`ReadOnlySpan<char> v = record.GetUnicodeString("Path")` bound to the **`string`** overload —
a `string` argument wins by identity conversion over the implicit span conversion — allocated,
and then converted implicitly to the span. It compiled with no warning and no diagnostic, so
the spelling that looked allocation-free was not. Overloading on the *out* parameter instead
was also measured and rejected: it makes every existing
`TryGetUnicodeString(name, out var v)` call site ambiguous (CS0121).

Keeping the two surfaces disjoint removes the question. If a handler needs to avoid
allocating, it moves to `OnEventRef`; there is no half-migrated state in which a call site
looks allocation-free but is not.

---

## Testing handlers

Tests that mock `IEventRecord` keep working. The interface is unchanged in shape, so an
existing `Mock<IEventRecord>` and every `It.IsAny<IEventRecord>()` compile and run against the
port as they did against the C++/CLI assembly.

Tests covering a handler you move to `OnEventRef` do not. `EventRecordRef` is a `ref struct`,
and a mocking framework cannot help with one at all:

- it cannot be a generic type argument, so `Mock<EventRecordRef>` and
  `It.IsAny<EventRecordRef>()` do not compile;
- it cannot appear in an expression tree, so `Setup` on a member that takes or returns one
  fails (CS8640, CS9244);
- it cannot be boxed, stored in a field, captured in a lambda, or returned from an `async`
  method or iterator.

Build a real record instead. `Testing.RecordBuilder` lays a payload out and `Testing.Proxy`
pushes it through the same dispatch path a live trace uses, so the handler sees exactly what
it would in production:

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

Three things about `RecordBuilder` that are easy to get wrong:

- **It needs a real, registered TDH schema.** `Pack()` resolves the layout from the provider's
  manifest on the machine running the test, so an invented provider GUID fails with
  `CouldNotFindSchema` (status 1168). Use an in-box provider whose schema you can rely on
  being present.
- **Use `PackIncomplete()` when the schema varies by Windows build.** `Pack()` requires every
  property in the schema to be supplied; events that gained properties in later releases will
  otherwise fail with "Not all the properties of the event were filled" on some machines.
- **There is no adder for binary or counted-string properties.** `AddValue<T>` covers the
  integral types. A counted string is a length-prefixed value in a `UNICODESTRING` property
  (`"\u0008abcd"` reads back as `"abcd"`), and `TryGetBinary` works against any property.

Assertions inside a ref handler have one constraint worth knowing: the record cannot be
captured, so `Assert.Throws(() => record.GetUnicodeString("Missing"))` does not compile. Use
an inline `try`/`catch` instead.

To pin that a handler really does not allocate, measure inside the callback. This works on
.NET Framework as well as modern .NET, but warm the schema and property caches with an
unmeasured pass first, and avoid accidentally boxing the value you keep alive:

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
