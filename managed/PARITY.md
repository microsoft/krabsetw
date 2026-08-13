# Parity with the C++/CLI implementation

`Microsoft.O365.Security.ETW` is a pure .NET reimplementation of the C++/CLI wrapper in
`Microsoft.O365.Security.Native.ETW`, which is itself a thin layer over the native
`krabs` headers. The two are meant to be drop-in interchangeable for consumers.

**Consumers should read `MIGRATION.md` instead.** It lists every public-surface difference
and what to do about it. This file is the engineering record behind those decisions: where
the two implementations deliberately differ and why, where they agree in a way that looks
wrong, and defects still open on one side or both.

The parity suite (`tests/ManagedETWTests`, compiled twice — once against each
implementation) is the mechanical check for everything else.

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

### Live-trace tests are scoped to the emitting process

The tests that start a real session use an `EventSource` whose GUID is derived from its
name, and the suite runs one test process per target framework concurrently. All of them
register the same provider, so a session in one process receives the events of the others:
a test asserting that no event of a given id arrives fails whenever a sibling process
happens to emit one. This was the cause of a long-standing intermittent failure in
`EndToEndTests` and, once the suite grew, a near-deterministic one in `EventIdFilterTests`.

Every live-trace filter that counts or reads the test `EventSource`'s events is now composed
with `EtwHarness.ThisProcess`. Suites that add such a test should do the same; without it a
green run only means the sibling processes were quiet. Tests that deliberately observe
system-wide activity — `RundownTests`, `KernelGroupMaskTests` — are the exception and say so.

## Deliberate divergences

### Testing surface beyond krabs

The `Testing` namespace gained surface the C++/CLI implementation never had, so a parity
diff shows it as additions.

`RecordBuilder` in krabs supplies integral properties only, which makes any event whose
template contains a pointer, GUID, FILETIME or SID unusable as a fixture — properties are
laid out sequentially, so an unsupported type part-way through a schema prevents everything
after it from being addressed. The port adds an adder for every in-type
`how_many_bytes_to_fill` already knew how to pad. It also drops the terminator on a string
the schema sizes, which krabs emits unconditionally; TDH consumes exactly the declared
number of characters, so the extra terminator displaced every later property.

`EventSchema` is new. It lets a test declare an event's layout rather than read it from the
machine's registered providers, which removes the requirement that a fixture's provider be
installed. The declaration is scoped to the execution context and is consulted by
`SchemaCache` on a miss, before TDH — so the hot path is untouched, and a trace that
declares nothing pays a single null check per distinct event. The risk it carries is that a
declaration can drift from the manifest it mirrors; `MIGRATION.md` says so where the feature
is documented.

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
nullable analysis. The public-surface differ ignores the `Nullable*` attributes for that
reason.

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

`MIGRATION.md` lists what was removed and what replaces it. The rationale, in each case,
is that nothing in the known consumer set used it:

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

The public surface is differenced by reading metadata directly rather than by reflection,
because one side is a mixed-mode C++/CLI binary that cannot be loaded on .NET. That differ
is kept out of tree; it does not compare custom attributes, so `[Obsolete]` differences are
invisible to it.

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

### ANSI decoding ignores the out-type (fixed in the port, open in C++/CLI)

Tracked internally.

`TDH_OUTTYPE_STRING` means the ANSI code page, but `TDH_OUTTYPE_UTF8` (35) and
`TDH_OUTTYPE_JSON` (34) mean UTF-8, and `TDH_OUTTYPE_XML` (28) defers to the document's
own encoding declaration. Neither implementation branched on the out-type; both decoded
ANSI string in-types using the ANSI code page unconditionally.

The port now selects the encoding from the out-type (`AnsiEncoding.ForOutType`), on the
decoding path (`IEventRecord.GetAnsiString`), in the comparison path (`AnsiString`
predicates transcode their comparison value both ways once, so matching stays a byte
compare), and in `RecordBuilder`, which encodes an ANSI value when the record is packed
rather than when it is supplied. `TDH_OUTTYPE_XML` is left on the ANSI code page:
honouring the document's declaration means parsing the value, and TDH does not re-encode
it either.

This is a divergence from C++/CLI until the same fix lands there, and the parity suite
cannot cover it in the meantime — the coverage is
`managed/tests/O365.Security.ETW.Managed.Tests/AnsiOutTypeTests.cs`, which declares an
`EventSchema` carrying `win:UTF8` and `win:Json` out-types.

A sweep of the 1503 providers registered on a build machine found 4163 ANSI-typed string
properties: 4162 `TDH_OUTTYPE_STRING`, one `win:Xml`, and zero UTF-8 or JSON. So the
exposure is currently theoretical.

The out-types actually consumed were then checked directly, rather than inferred from that
sweep, by decoding live events:

| Shape | Out-type | Encoding |
| --- | --- | --- |
| Manifest `win:AnsiString`/`xs:string` (WinINet 1057, WinRM 1044, CodeIntegrity 3076-3119) | 1 (`STRING`) | ANSI code page |
| TraceLogging ANSI string (`TraceLoggingValue(const char*)`) | 0 (`NULL`) | ANSI code page |

Both decode byte `0xE9` as `U+00E9`, i.e. identically to C++/CLI. `AnsiConsumerShapeTests`
pins these two shapes plus the UTF-8 one, and pins them on the **bytes**: comparing only the
decoded string cannot detect a wrong encoding, because `RecordBuilder` encodes through the
same out-type lookup the reader decodes with, so changing it changes both sides and the
round trip still succeeds.

Note that `TdhOutType` in the port had these two values numbered three too high until
recently; the enum in `tdh.h` is implicitly numbered and the transcription had drifted.
Values are now spelled out explicitly.

### C++/CLI truncates ANSI strings at an embedded NUL

`EventRecord.hpp` decodes via `gcnew String(str.c_str())`, which stops at the first NUL.
The port decodes the full property length. Only reachable for ANSI in-types that are not
NUL-terminated, i.e. the counted and non-NUL-terminated variants.

## Resolved

### An empty array was sized as one element

A property whose element count comes from the payload (`PropertyParamCount`) can legitimately
have no elements, in which case it occupies no bytes. The sizer collapsed a count of zero to
one element, which is right for a *schema* count — TDH uses zero there to mean "scalar" — and
wrong for a payload-derived one, so an empty array consumed one element's worth and moved
every property after it.

The two cases are now distinguished by the caller, which is the only place that knows which
kind of count it read. Covered by `DynamicArrayCountTests`, which logs a real TraceLogging
event with a 0-, 1- and 3-element array and reads back the scalar that follows it; the
zero-element case fails without the fix.

krabs cannot have this bug: it does not walk arrays itself, it asks
`TdhGetPropertySize` for every property whose size is not immediately available.

### The provider set was published as two separate arrays

Enabling a provider on a running trace is the one thing a trace does from two threads at
once: the caller replaces the provider set while the processing thread is scanning it. The
set was two fields — the providers and their GUIDs, indexed alike — assigned one after the
other with no barrier, and the routing loop bounded its scan by the GUID array's length
while indexing the provider array. A processing thread that saw the new GUID array against
the old provider array would index past its end.

Both are now held in one immutable `Routes<T>` swapped with a single `Volatile.Write`, and
the routing loop takes one `Volatile.Read` per event, so it sees either the whole of the old
set or the whole of the new one. This costs nothing on the hot path: a volatile reference
read is a plain load on x86/x64, and the allocation-free tests are unchanged.

The race itself is not directly testable — it needs the two threads to interleave inside a
window a few instructions wide. `EnableWhileRunningTests` covers the functional half:
a provider enabled mid-run receives events, and the one enabled before `Start` keeps
receiving them afterwards. Nothing covered enable-while-running before.

### `Stop` freed state the processing thread was still reading through

`Stop` released the trace's callback registration and its logger name, having waited for
`ProcessTrace` to return first — because the callback thread reads through both — and then
discarded the wait's result. A wait that timed out fell straight through to the teardown it
existed to prevent, turning a wedged trace into an access violation on a thread the caller
does not control.

Making the timeout loud turned out to be the wrong fix, because the wait was itself the
problem. `Stop` held `_gate` across it, and `Enable` takes `_gate`, so a handler that called
back into its own trace deadlocked both: the handler blocked on the lock, so `ProcessTrace`
could not return, so the wait could not complete. Reproduced — `Stop` took exactly the
30-second timeout, every time.

`Stop` is now a signal, as it is in krabs (`stop_trace` then `close_trace`, no wait) and in
C++/CLI. It does not wait and releases nothing, so it cannot deadlock and cannot free
anything early. `Dispose` inherits the wait and the release, and does the waiting outside
the lock. That is safe where `Stop` was not: `Dispose` is called by whoever owns the trace,
after they are done with it, and a handler reaching it would mean the owner had already
given up ownership. Disposing *from* a handler is still detected and skips the release
rather than freeing underneath the frames below it.

Because the registration now outlives `Stop`, `Open` reuses it rather than taking a fresh
one per cycle — otherwise every `Open`/`Stop` pair would leak a slot. `StopAndDisposeTests`
covers all three: that `Stop` returns promptly with a handler calling back into the trace,
that repeated cycles do not accumulate registrations, and that `Dispose` releases without an
explicit `Stop`.

`_processingThread` is volatile now: it is written by the processing thread and read by
whichever thread disposes, and a stale read would skip the wait entirely.

### A TraceLogging event was identified by its name, not its schema

A self-describing event carries its own schema in an extended-data block, and native
TraceLogging leaves `EVENT_DESCRIPTOR.Id` at 0 — unlike `EventSource`, which assigns an id
per `Write<T>` call site (measured: 153 and 154 for two shapes). So for a native provider the
whole descriptor is identical across every event, and the metadata block is the only thing
separating one event's layout from another's. The cache keyed on the event *name*, which is
not enough, and krabs keys the same way (`schema_key::name`).

Measured against a real native provider, two distinct failures:

- **Two same-named events with different fields.** The first schema was applied to both, so
  one shape decoded as the other: 964 of 1434 events returned a wrong value for a field
  present in both — a plausible integer, no error.
- **A rolling upgrade that appended a field.** The old schema stayed cached and the new field
  was never readable, 0 times out of 193, with no indication anything was missing. Reversed,
  with the new schema cached first, old events correctly reported the field absent.

A version that *inserts* rather than appends corrupts instead of hiding: every field after
the insertion point shifts. And which layout wins is a race — whichever the trace sees first
— so the same binaries can behave differently between runs.

The key is now the hash of the whole metadata block, and collisions are resolved by
comparing the block rather than the name. Each distinct field layout gets its own entry.
Covered by `TraceLoggingSchemaKeyTests`; reverting to the name fails two of its three cases.

This matters most for a provider whose emitters can be different versions at once. HostIDS's
Detours provider injects into other processes, so an old injected binary can outlive an agent
upgrade by as long as the host process runs.

### Unmanaged memory had no finalizer behind it

`Marshal.AllocHGlobal` is not reclaimed by the collector, so every allocation needed a
last-resort release as well as `IDisposable` — otherwise abandoning an owner leaked for the
life of the process, and `Dispose` was load-bearing rather than merely correct. Only
`SynthRecord` had one.

Each allocation is now a `SafeHGlobalHandle`, so it releases *itself*: the schema blobs, the
trace logger names, and the synthetic record's three buffers. The types that merely hold
allocations no longer need finalizers at all, and the release is *critical* finalization —
`SafeHandle` derives from `CriticalFinalizerObject`, so it runs after ordinary finalizers.
That ordering is what makes the logger name safe: ETW reads it for as long as the trace
handle is open, and the trace's own ordinary finalizer is what closes that handle.

The consumer handle from `OpenTrace` is deliberately **not** a `SafeHandle`. It is a
`TraceHandle`, a `CriticalFinalizerObject` holding the `ULONG64` directly, for two reasons.
A `SafeHandle` stores an `IntPtr`, and squeezing a `TRACEHANDLE` into a 32-bit one is lossy
above 32 bits — measured: `0x0000000100000000` converts back as `0`. The documented failure
value is `(UINT64)UINTPTR_MAX`, which implies real handles are pointer-shaped, but that is an
inference from the sentinel rather than a guarantee, and the sentinel itself differs between
pre-Vista and Vista+. Second, `SafeHandle`'s reference counting is backwards here: ETW
requires `CloseTrace` to be callable *while* `ProcessTrace` runs — that is how processing is
stopped — whereas a ref count taken around the call would defer the close.

The traces keep an ordinary finalizer for what remains theirs: the session, and the callback
registration. `Start` also keeps the trace reachable across `ProcessTrace` with
`GC.KeepAlive`, so a trace cannot be finalized while ETW still holds its logger name and
context.

Covered by `FinalizerTests`, which abandons each type inside a non-inlined helper, collects,
and checks that `SafeHGlobalHandle.LiveAllocations` returns to its baseline.

krabs needs none of this — its allocations are `std::unique_ptr` and `std::vector` members,
released by the destructor when the trace object dies.

### The trace registry rooted the consumer's object graph

ETW hands back an opaque context on every event, so a trace has to be findable from a static
table. That table held its entries strongly, and the entry is the thin end of a very long
wedge: a trace context reaches the providers enabled on it, which reach the consumer's event
handlers, which routinely close over the trace itself — to stop it, to enable another
provider, to read its stats.

So the static rooted the trace, which meant the trace's finalizer never ran, which meant it
never unregistered. A cycle nothing could break, holding the consumer's entire object graph
for the life of the process. Demonstrated with a weak reference to a canary object captured
by a handler: collected when the handler does not touch the trace, immortal when it does.

The table now holds weak references. The only strong reference to a context is its trace's
own field, and the callback path stays correct because a trace cannot be collected while it
is inside `ProcessTrace`. Slots whose target has been collected are handed out again, and
`Unregister` only clears a slot that still holds the context it was given, so a slot reused
between a trace becoming unreachable and its finalizer running cannot be wiped by the wrong
owner.

The cost is one weak dereference per event in place of an array load: measured at 0.9 ns on
.NET 8 and 3.8 ns on .NET Framework, against a decode of roughly 250 ns.
`TraceRegistryLifetimeTests` covers it, and fails if the entries are made strong again.

This has no analogue in krabs, whose callback context is the address of the caller's own
trace object and whose providers are held by reference.

### `RecordBuilder` mis-padded an unfilled `Sid`

An unfilled property is padded so that the properties after it stay where the schema says
they are. A SID's width is not fixed, but a *zeroed* one is: the reader takes the size from
the SubAuthorityCount byte, and zero sub-authorities leaves the fixed
Revision(1) SubAuthorityCount(1) IdentifierAuthority(6) header, so it is always eight bytes.
The port padded the record's pointer width instead — correct on a 64-bit record by
coincidence, four bytes short on a 32-bit one, where the reader then swallowed the first
half of the next property. Now always eight. Covered by `UnfilledPropertyTests`.

krabs pads `sizeof(PSID)` and has the same defect, with the same coincidence hiding it.

### A synthetic payload of 64 KiB or more wrapped silently

`EVENT_RECORD.UserDataLength` is a `USHORT`, and `SynthRecord` cast the payload length into
it. A larger payload wrapped, so the record decoded as a much shorter one and every property
past the wrapped length was reported absent — a fixture failing for a reason nowhere near
the code under test. `Pack` now refuses to build it. Covered by `OversizedRecordTests`,
which also pins the largest payload that still fits.

### A cached schema baked in the emitting process's pointer width

`PropertyTable` precomputes the byte offset of every property whose size the schema
already knows, which is what makes a hot-path read a subtraction rather than a walk. A
`win:Pointer` property's size is not a property of the schema, though — it is four bytes
or eight depending on the process that emitted the event. `SchemaKey` did not include the
pointer width, so the first event to populate an entry fixed the offsets for every later
event of that kind, and the same event emitted by a WoW64 and a native process shared one
set. Everything after the pointer was then read four bytes out. Where the wrong offset
still landed inside `UserDataLength` it produced a wrong value with no error at all.

krabs is immune because it derives the pointer width per event
(`size_provider::get_property_size`) and caches no offsets. This is port-only, and
mixed-bitness providers are ordinary: any manifest provider used from both a 32-bit and a
64-bit process on the same machine hits it.

The pointer width is now part of the cache key, so the two bitnesses get separate entries.
Covered by `SchemaCacheTests.EventsDifferingOnlyInOneIdentityFieldGetDifferentSchemas`
(the `pointerSize` case) and, end to end,
`RecordBuilderTypeTests.TheSameEventFromBothPointerWidthsDecodesWithItsOwnOffsets`, which
pushes both widths through one trace in both orders.

### Group-mask kernel providers used the wrong information class

`EVENT_TRACE_INFORMATION_CLASS` is undocumented and absent from the SDK headers; krabs
declares it in `perfinfo_groupmask.hpp`, where `EventTraceGroupMaskInformation` is the
second member and so has the value 1. The port had transcribed it as 3, which is
`EventTraceTimeProfileInformation`. Every kernel provider without an `EVENT_TRACE_FLAG_`
bit — including the in-box `ObjectManagerProvider` — therefore failed to enable:
`NtQuerySystemInformation` returns `0xC0000004` and `KernelTrace.Open` throws.

Nothing else caught this. `LayoutFacts` and `layoutprobe` validate struct layouts, not
enum values, and no test exercised a group-mask provider. Covered now by
`KernelGroupMaskTests`, which asks the kernel rather than asserting the constant; it fails
with the old value on a live machine.

### Rundown was requested during `Open` rather than before `ProcessTrace`

krabs issues `EVENT_CONTROL_CODE_CAPTURE_STATE` from `process_trace`, immediately before
`ProcessTrace`, with a comment recording that the timing was found to matter. The port
issued it from `EnableMerged`, i.e. during `Open`. Because `Open` and `Start` are separate
public calls here — they are one call in krabs — the gap in front of `ProcessTrace` was
unbounded rather than merely early.

Now issued from `Start`, immediately before `ProcessTrace`, matching krabs. A provider
enabled *after* `Start` has already passed that point gets its own `CAPTURE_STATE` from
`Enable`, since there is no later one to wait for; krabs cannot reach that state at all,
because it has no public `Enable`-while-running.

An honest note on evidence: this change restores krabs' ordering, but the loss it is meant
to prevent could not be reproduced on Windows 11 with Kernel-Process. `RundownTests`
pauses two seconds between `Open` and `Start` and the rundown events still arrive; so do
they with a 20-second pause, a 4 KB two-buffer session and continuous process churn to
force the ring to wrap. `RundownTests` is therefore a regression test that rundown works
at all — which nothing covered before — not a demonstration of the timing bug.

### A zero FILETIME was reported as a missing property

`TryGetDateTime` rejected any FILETIME `<= 0`. Zero is not an error value: providers use
it to mean "no timestamp", and `DateTime.FromFileTimeUtc(0)` returns `1601-01-01T00:00:00Z`
rather than throwing, which is exactly what C++/CLI's
`DateTime::FromFileTimeUtc(largeInt->QuadPart)` returns. The port instead reported the
property as unreadable, and `GetDateTime` raised `ParserException("Could not find property
in event schema")` for a property that was present and well-formed.

Now only genuinely negative values are refused — those are the ones `FromFileTimeUtc`
rejects, and refusing them keeps `TryGetDateTime` non-throwing. Covered by
`FileTimeBoundaryTests`.

### `RecordBuilder` accepted a fixed-width binary of the wrong length

A `win:Binary` property with a schema-declared length carries no length of its own: the
reader takes the width from the schema and ignores the value. `Pack` validated the
in-type but not the length, so a fixture supplying a different number of bytes produced a
record no provider could emit, with every later property shifted. Strings were already
validated this way (`RequireDeclaredLength`); binaries are now too. Covered by
`FixedWidthBinaryTests`.

krabs has the same gap in `record_builder.hpp`, and like the pointer padding defect it is
only reachable through the testing surface.

### A synthetic record could be finalized while it was being read

`SynthRecord` owns its `EVENT_RECORD`, user data and extended data in unmanaged memory and
releases them from a finalizer. `Proxy.PushEvent` and `Predicate.Test` took the raw pointer
out of the record and dispatched through it, and in the shape every example uses —
`proxy.PushEvent(builder.Pack())` — nothing else referenced the record for the duration of
the callback. A collection landing inside a handler was therefore free to finalize the
record and free the payload while it was being read, which surfaced as an
`AccessViolationException` from a handler that had done nothing wrong.

Both call sites now keep the record alive across dispatch. Covered by
`SynthRecordLifetimeTests`, which collects from inside the ref handler, the compat handler
and a predicate; two of the three faulted reliably on net48 before the fix.

This has no analogue in krabs, whose records are not garbage collected.

### `RecordBuilder` padded unfilled pointers to the wrong width

A filled `win:Pointer` property is emitted at the width the record's header flags declare,
but an unfilled one padded `IntPtr.Size` bytes — the width of a pointer in the process
running the test. Building a 32-bit-source record with an unfilled pointer therefore
misplaced every property after it. Both now use the record's own width.

krabs has the same defect (`how_many_bytes_to_fill` pads `sizeof(void*)`), and it is only
reachable through the testing surface.

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
