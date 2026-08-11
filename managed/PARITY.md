# Parity with the C++/CLI implementation

`Microsoft.O365.Security.ETW` is a pure .NET reimplementation of the C++/CLI wrapper in
`Microsoft.O365.Security.Native.ETW`, which is itself a thin layer over the native
`krabs` headers. The two are meant to be drop-in interchangeable for consumers.

## Migrating from `Microsoft.O365.Security.Native.ETW`

The port ships as a **different package**, `Microsoft.O365.Security.ETW`, starting at
**5.0.0**. The C++/CLI package continues on the 4.4.x line, so the two can be installed
side by side while consumers migrate. The old id kept "Native" in the name, which no
longer describes anything about this implementation.

| | `Microsoft.O365.Security.Native.ETW` | `Microsoft.O365.Security.ETW` |
| --- | --- | --- |
| Package version | 4.4.x | 5.0.0 |
| Assembly | `Microsoft.O365.Security.Native.ETW.dll` | `Microsoft.O365.Security.ETW.dll` |
| Namespace | `Microsoft.O365.Security.ETW` | *unchanged* |
| Target frameworks | net462, net8.0 | net462, net48, net8.0-windows, net10.0-windows |
| Architecture | x64 and ARM64 mixed-mode, under `runtimes/` | one AnyCPU assembly under `lib/` |

Because the namespace is unchanged, most source compiles untouched — swapping the
`PackageReference` is usually the whole migration. The assembly name *does* change, so
this is not binary-compatible: anything already compiled against the old assembly must be
recompiled, and `Assembly.Load` calls or binding redirects naming
`Microsoft.O365.Security.Native.ETW` need updating.

The public surface is deliberately not identical. Every difference is enumerated in
`tools/ApiDiff/ApprovedDifferences.txt` and gated in CI; the ones that can break a
compile are described under Deliberate divergences below, of which
`IEventRecord.GetDateTime` is the one most likely to affect you.

The parity suite (`tests/ManagedETWTests`, compiled twice — once against each
implementation) is the mechanical check. This file records the things that suite
*cannot* tell you: where the two implementations deliberately differ, where they agree
in a way that looks wrong, and known defects that are still open on one side or both.

### Unit tests

Tests that mock `IEventRecord` keep working. The interface is unchanged in shape, so an
existing `Mock<IEventRecord>` and every `It.IsAny<IEventRecord>()` compile and run against
the port as they did against the C++/CLI assembly.

Tests covering a handler you move to `OnEventRef` do not. `EventRecordRef` is a `ref
struct`, and a mocking framework cannot help with one at all:

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

- **It needs a real, registered TDH schema.** `Pack()` resolves the layout from the
  provider's manifest on the machine running the test, so an invented provider GUID fails
  with `CouldNotFindSchema` (status 1168). Use an in-box provider whose schema you can rely
  on being present.
- **Use `PackIncomplete()` when the schema varies by Windows build.** `Pack()` requires every
  property in the schema to be supplied; events that gained properties in later releases will
  otherwise fail with "Not all the properties of the event were filled" on some machines.
- **There is no adder for binary or counted-string properties.** `AddValue<T>` covers the
  integral types. A counted string is a length-prefixed value in a `UNICODESTRING` property
  (`"\u0008abcd"` reads back as `"abcd"`), and `TryGetBinary` works against any property.

Assertions inside a ref handler have one constraint worth knowing: the record cannot be
captured, so `Assert.Throws(() => record.GetUnicodeString("Missing"))` does not compile.
Use an inline `try`/`catch` instead.

To pin that a handler really does not allocate, measure inside the callback. This works on
.NET Framework as well as modern .NET, but warm the schema and property caches with an
unmeasured pass first, and avoid accidentally boxing the value you keep alive:

```csharp
long before = GC.GetAllocatedBytesForCurrentThread();
// ... exercise the accessors ...
Assert.Equal(0, GC.GetAllocatedBytesForCurrentThread() - before);
```

`managed/tests/O365.Security.ETW.Managed.Tests/RefAccessorTests.cs` is a worked example of
all of the above.
## Why the parity suite is not sufficient on its own

The parity tests are written against behaviour krabs already has, so they only exercise
mechanisms that exist in both implementations. Anything the port *added* is invisible to
them by construction.

The clearest example: both implementations memoise resolved offsets behind a high-water
mark, but they are separate implementations of that memoisation, and a divergence between
them is not expressible as a parity failure — the parity tests read properties in schema
order, which is the one access pattern under which a memoisation bug cannot show up.

A bug of exactly that shape shipped in the port and was found by accident (see
`OffsetResolverTests`): reading a late property and then an early one returned -1 for the
early one, which krabs gets right. The general guard is
`OffsetResolverDifferentialTests`, which differences memoised resolution against a fresh
resolver per access.

Note that krabs memoises too — `parser::find_property` keeps `propertyCache_`, a
`lastPropertyIndex_` high-water mark and a `nextHint_` scan hint. Earlier revisions of
this file claimed krabs resolved every offset from scratch; that was wrong, and the
caching was added as a performance change.

Tests covering port-only state live in `managed/tests/O365.Security.ETW.Managed.Tests`
and should be validated by mutation — reintroduce the defect and confirm the test fails —
rather than assumed to work.

## Deliberate divergences

### Case folding above U+007F

`SpanCompare.ToUpper(char)` folds ASCII inline and falls back to
`char.ToUpperInvariant` for everything else. krabs uses the CRT's `towupper`, and
because nothing in the codebase ever calls `setlocale`, the CRT stays in the `"C"`
locale and folds ASCII only.

So the port case-folds *more* than C++/CLI does. A case-insensitive filter written
against a non-ASCII string will match in the port where it would not have matched in
C++/CLI.

This is intentional. The alternative — matching krabs by restricting to ASCII — makes
case-insensitive matching silently ineffective for non-ASCII input, which in a security
filter means missed detections rather than extra ones. Kept as an improvement.

Note the byte overload, `SpanCompare.ToUpper(byte)`, is ASCII-only in both
implementations: case folding a single byte is not well defined without knowing the code
page.

### `DateTime` property signature

C++/CLI declared `GetDateTime` as `DateTime^` — a *boxed* value type, which surfaces to C#
as `System.ValueType`. The port returns `DateTime`, dropping the boxing allocation.

This is a breaking change, taken deliberately as part of the major version bump:

* Implementors of `IEventRecord` break at compile time. C# requires an exact signature
  match for interface implementation — there is no return-type covariance — so a class
  declaring `public ValueType GetDateTime(string)` no longer implements the member.
* `TryGetDateTime(name, out ValueType v)` breaks for the same reason: `out` parameters
  require exact type identity.
* Callers of the return value are mostly unaffected; `ValueType x = record.GetDateTime(…)`
  still compiles via implicit boxing. Only `var` inference shifts.
* Binary compatibility is not preserved. Assemblies compiled against 4.4.9 must be
  recompiled or they will throw `MissingMethodException`.

The one capability genuinely lost is that `null` was a *distinguishable* "no value"
sentinel, where `default(DateTime)` is a legal date. That is the situation `GetUInt32` has
always been in — `0` was never distinguishable either — so this makes `DateTime`
consistent with the rest of the API rather than an outlier.

`SYSTEMTIME`-shaped payloads are decoded with `DateTimeKind.Utc` assumed rather than read
from the out-type. That assumption is port-only new behaviour — krabs' `GetValue<FILETIME>`
rejects a 16-byte property outright — and is folded into the ANSI out-type defect below.

### `TryGet*` leaves nothing behind on failure

krabs assigns the out parameter only on success:

```cpp
// EventRecord.hpp:853
if (success) result = value;
```

`[Out]` in C++/CLI is metadata only — the CLR does not enforce assignment — so a failed
lookup leaves the caller's variable holding whatever it held before the call. The port
writes the default first, so a failed lookup always zeroes it.

```csharp
uint v = 42;
if (!record.TryGetUInt32("missing", out v)) { /* C++/CLI: 42    port: 0 */ }
```

This applies uniformly to every `TryGet*`, not just `TryGetDateTime`. The port's behaviour
is deterministic and is kept.

### `KernelProvider` group mask narrowed to `uint`

Native `PERFINFO_MASK` is `typedef ULONG` (`krabs/perfinfo_groupmask.hpp:16`), and C++/CLI
mirrored it as `UInt32`. The port originally widened it to `ulong` and then truncated it
back at the only consumption site in `KernelTrace.EnableGroupMasks`, so any bit above 32
was silently discarded. Narrowed to `uint`, which restores the C++/CLI signature and makes
the invalid value unrepresentable.

### `TraceStats` is a `readonly struct`

C++/CLI declared `TraceStats` as a mutable value type with public mutable fields. The port
declares it `readonly struct` with an internal constructor. Reading fields — the only thing
consumers do with it — is unchanged, as is `new TraceStats()`, so this is source-compatible.
Assigning a field on a `TraceStats` local no longer compiles, but nothing in the ecosystem
did that: the type is only ever produced by `UserTrace.QueryStats`/`KernelTrace.QueryStats`.
It is a binary-breaking change, which costs nothing here because the assembly rename already
forces every consumer to recompile.

### Nullable reference annotations

The library is compiled with `<Nullable>enable</Nullable>` and its public surface is
annotated, so consumers that opt into nullable reference types get accurate diagnostics
instead of the "oblivious" default. The `TryGet*` methods carry `[MaybeNullWhen(false)]`,
which is what lets `if (record.TryGetUnicodeString(name, out var s))` narrow `s` to
non-null in the true branch without a redundant null check.

`[MaybeNullWhen]` and `[NotNullWhen]` do not exist in the net462/net48 reference assemblies,
so `Interop/NullableAttributes.cs` declares them under `#if !NET`. Roslyn matches these
attributes by full name rather than by identity, so an `internal` declaration is honoured by
external consumers compiling against net462/net48.

Annotations are metadata only; they cannot break a compile that was not already opted into
nullable analysis, and `tools/ApiDiff` deliberately ignores the `Nullable*` attributes for
that reason.

### The allocation-free surface is `EventRecordRef` only

There are two ways to receive an event, and the split is deliberate.

| | Callback | Record type | Allocates |
| --- | --- | --- | --- |
| Compat | `OnEvent` / `DefaultEvent` | `IEventRecord` | yes |
| Allocation-free | `OnEventRef` / `DefaultEventRef` | `EventRecordRef` | no |

`IEventRecord` is the compat surface, and every one of its getters allocates: the payload
lives in the ETW buffer, and returning a `string` or a `byte[]` means copying out of it.
The adapter itself is reused for the life of the trace, so the allocation is entirely in
the return types.

`EventRecordRef` has no such problem — it hands back `ReadOnlySpan<T>` views straight into
the buffer. It is a `ref struct`, so it can never implement an interface; reaching it means
subscribing `OnEventRef` instead of `OnEvent`. The returned spans are views into the ETW
buffer and are valid only for the duration of the callback, exactly like the record itself.

**Handlers must declare their parameter explicitly.** `EventRecordDelegate` takes
`in EventRecordRef`, and a lambda cannot infer a parameter modifier, so an implicitly typed
lambda will not bind:

```csharp
provider.OnEventRef += (in EventRecordRef record) => { ... };   // required
provider.OnEventRef += record => { ... };                       // does not compile
```

**Why span accessors are not offered on `IEventRecord`.** An earlier revision added six
span-returning members to `IEventRecord` so a consumer could migrate one call site at a time.
They were removed before release. Overloading on the *name* parameter meant
`ReadOnlySpan<char> v = record.GetUnicodeString("Path")` bound to the `string` overload — a
`string` argument wins by identity conversion over the implicit span conversion — allocated,
and then converted implicitly to the span. It compiled with no warning and no diagnostic, so
the spelling that looks allocation-free was not. Overloading on the *out* parameter instead
was also measured and rejected: it makes every existing `TryGetUnicodeString(name, out var v)`
call site ambiguous (CS0121).

Keeping the two surfaces disjoint removes the question. If a handler needs to avoid
allocating, it moves to `OnEventRef`; there is no half-migrated state in which a call site
looks allocation-free but is not.

**What `EventRecordRef` does not have.** There is no span form of the IP-address or socket
-address accessors, because `IPAddress` and `SocketAddress` are classes; no `GetAnsiString`,
because transcoding from the provider's ANSI code page is what forces the allocation
(`TryGetAnsiStringBytes` returns the raw bytes instead, a suffix following
`AsnDecoder.TryReadPrimitiveCharacterStringBytes`); and no `Properties` enumeration. A
handler that needs those stays on `IEventRecord`.
### Public surface that was removed

`managed/tools/ApiDiff` compares the public surface of two assemblies by reading metadata
directly — one side is a mixed-mode C++/CLI binary that cannot be loaded for reflection on
.NET. Run it against the C++/CLI net462 output and the port's to reproduce this list.

Deliberately not restored, because nothing in the known consumer set uses them:

| Removed | Reason |
| --- | --- |
| `EventRecord`, `EventRecordMetadata` classes | The port's adapter is reused and mutated per event; naming it publicly makes "hold it past the callback" look supported. C++/CLI also exposed public `_EVENT_HEADER*` / `_EVENT_RECORD*` fields with no C# equivalent. |
| `PropertyEnumerable`, `PropertyEnumerator` | Allocates a `Property` per property; unused. |
| `IDisposable` on `Predicate`, `Property`, `KernelProvider`, `RawProvider` | These held a `NativePtr<T>` in C++/CLI, so disposal freed C-runtime heap. The port's equivalents are plain managed objects with nothing to release; an empty `Dispose` would imply ownership that does not exist. |
| `IUserTrace.Enable(RawProvider)` | `RawProvider` is `[Obsolete]` in both implementations; the replacement is `Provider.OnMetadata`. |
| `Property.Type`, 3-argument `Property` ctor, `OutType` as `int` | The port exposes `InType`/`OutType`/`Length` as `uint`. Unused. |
| `EventHeaderProperty.LEGACY_EVENTLOG`, `FORWARDED_XML` | Renamed to `LegacyEventLog`, `ForwardedXML`. |
| `EventTraceProperties` public fields | Now properties. Object-initializer syntax is unaffected; only `ref`/`out` use breaks. |

`IEventRecordError` *was* restored — `EventRecordError` implements it — because
`EventRecordErrorDelegate` is declared in terms of it and the interface is mocked by
consumers.

Note the differ does not currently compare custom attributes, so `[Obsolete]` differences
are invisible to it.

### Structs are not decoded

The port returns -1 from `OffsetResolver.SizeOf` for a property carrying
`PropertyStruct` rather than attempting to size it, which makes that property and
everything after it unreadable. This was scoped out of the initial milestone and has not
been revisited.

krabs does not decode structs either, and fails worse — see below. Nothing that worked
before stops working, but the failure mode changes from silent corruption to a visible
failure. Tracked internally.

## Things that look like divergences and are not

### `TDH_INTYPE_MANIFEST_COUNTEDBINARY` length prefix

Both implementations include the two-byte length prefix in the returned buffer. krabs
has no special handling for the type, `krabs::binary` is a raw byte copy, and
`TdhGetPropertySize` reports the size including the prefix. The port matches.

An earlier review noted this as a divergence. That note was wrong.

### Oversized fixed-width properties

`TryGetFixed` requires an exact size match, so a fixed-width read against a property
whose schema length disagrees fails rather than truncating. This matches krabs. An
earlier note claiming the port truncated was stale.

## Known defects

### krabs mis-sizes struct properties (open, C++ side, affects shipping code)

Tracked internally.

`krabs/size_provider.hpp` checks `PropertyParamLength` and `propertyInfo.length`, but
never tests the `PropertyStruct` flag before reading `propertyInfo.nonStructType.InType`.
For a struct property that union member holds a struct-member start index and count, so
krabs interprets a member index as a TDH in-type, derives a size from it, and silently
misaligns every subsequent property in the event.

This is a real bug in the shipping implementation. It is untested on both sides. The
port avoids it by refusing to size structs at all, which fails visibly instead.

Struct properties are not rare: 1148 events across 88 of the 1503 providers registered on
a build machine declare one, including three providers in common use (SMBClient,
BITS-Client, Hyper-V-Compute). That does not by itself establish
impact — a read only breaks if it targets a property at or after the struct in the same
event — but it does rule out "no provider does this".

### ANSI decoding ignores the out-type (open, both sides)

Tracked internally.

`TDH_OUTTYPE_STRING` means the ANSI code page, but `TDH_OUTTYPE_UTF8` (35) and
`TDH_OUTTYPE_JSON` (34) mean UTF-8, and `TDH_OUTTYPE_XML` (28) defers to the document's
own encoding declaration. Neither implementation branches on the out-type; both decode
ANSI string in-types using the ANSI code page unconditionally.

A sweep of the 1503 providers registered on a build machine found 4163 ANSI-typed string
properties: 4162 `TDH_OUTTYPE_STRING`, one `win:Xml`, and zero UTF-8 or JSON. So this is
currently theoretical. Tracked separately for both implementations.

Note that `TdhOutType` in the port had these two values numbered three too high until
recently; the enum in `tdh.h` is implicitly numbered and the transcription had drifted.
Values are now spelled out explicitly.

### C++/CLI truncates ANSI strings at an embedded NUL

`EventRecord.hpp` decodes via `gcnew String(str.c_str())`, which stops at the first NUL.
The port decodes the full property length. Only reachable for ANSI in-types that are not
NUL-terminated, i.e. the counted and non-NUL-terminated variants.

## Resolved

### ANSI string decoding used UTF-8

The port decoded `TDH_INTYPE_ANSISTRING` and friends as UTF-8, so any byte above 0x7F
became U+FFFD — lossy and unrecoverable. C++/CLI was already correct
(`marshal_as<std::string>` and `gcnew String(const char*)` are both CP_ACP).

Fixed by `Interop.AnsiEncoding`, which resolves the code page from `GetACP()`.
`Encoding.Default` is not usable here: it is CP_ACP on .NET Framework but UTF-8 on .NET,
which would make the two target frameworks disagree.

Covered by `describe_EventRecord.it_should_parse_ansi_strings_outside_of_ascii`, which
runs against both implementations.

It then regressed on net8.0 when that target framework was added, because the
`CodePagesEncodingProvider` registration inside `AnsiEncoding` was guarded with
`#if NET10_0_OR_GREATER`. Without the provider, `Encoding.GetEncoding` throws
`NotSupportedException` for any code page outside the handful .NET ships in the box, and
the `catch` fell back to exactly the `Encoding.Default` the previous paragraph rules out.
The guard is now `#if NET`, which covers every .NET (Core) target.

Two lessons worth keeping. A version-specific guard on a framework-family behaviour is a
latent bug that only shows up when someone adds a target framework. And the fallback made
the failure silent — it produced plausible wrong text rather than throwing.
`AnsiEncodingTests.UsesTheMachineAnsiCodePage` is what caught it, and it only ran on
net8.0 because the test project targets every framework the library does. Keep it that
way.
