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

### Records are invalidated when the callback returns

C++/CLI hands the callback an `EventRecordMetadata` (or a subclass) that wraps a raw
`EVENT_RECORD*`. That pointer is only ever assigned — the constructor and `Update` set
`record_` and `header_`, and nothing ever clears them (`EventRecordMetadata.hpp:26-41`).
`CallbackBridge` keeps one such instance per bridge and calls `Update` on it for each event
(`Callbacks.hpp:75-88`). A consumer that stores the `IEventRecord^` past the callback
therefore reads either freed memory or, once the next event arrives, that event's data —
silently, with no diagnostic. Native krabs has the same lifetime and relies on convention.

The port keeps the same reuse — one adapter per trace, rebound per event, so the hot path
still allocates nothing — but clears the pointer when the callback returns. A stashed record
throws `ObjectDisposedException` on its next use instead of returning another event's data.

Callers that never stashed a record see no behavioural change. Callers that did were already
broken; they now find out. The invalidation is a single field store on the normal path:
`TraceContext.OnEvent` carries no exception handler, and the exceptional path is covered by
the callers that already own an EH region (`TraceCallbacks.Dispatch`, `Testing.Proxy.PushEvent`).

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

### Value conversions that differ at the edges

Three conversions on the compat surface behave differently from C++/CLI at inputs that are
degenerate or out of range. All three are cases where C++/CLI's behaviour is hard to defend
on its own terms, so the port did not reproduce it.

**A FILETIME outside the DateTime range is reported as unreadable rather than throwing.**
C++/CLI hands the raw value to `DateTime::FromFileTimeUtc` *outside* its try/catch
(`EventRecord.hpp:441-480`), so a FILETIME that is negative or past 9999-12-31 — neither is a
representable time — throws `ArgumentOutOfRangeException` out of `TryGetDateTime` as well as
`GetDateTime`. A `TryGet` that throws defeats the point of the pattern, so the port's
`TryGetDateTime` returns `false` and `GetDateTime` then throws
`ParserException` like any other unreadable property. The exception type a caller sees
changes; a caller using the `TryGet` form no longer needs a `try` around it.

**A `SocketAddress` is sized from the property, not from the address family.** C++/CLI
builds `gcnew SocketAddress(family)` — which takes the family's *default* length — and then
copies a fixed `sizeof(sockaddr_in)` (16) or `sizeof(sockaddr_in6)` (28) bytes depending on
`ss_family`, reading out of a 128-byte `sockaddr_storage` into which only the property's
bytes were copied (`EventRecord.hpp:874-887`, `parse_types.hpp:187`). Anything not
`AF_INET` is treated as v6 and reads 28 bytes regardless of how many the property actually
had, so a shorter property yields whatever was left in the storage buffer. The port sizes
the result from the property's own length and copies exactly that. `SocketAddress.Size` and
the trailing bytes therefore differ for any property whose length is not exactly 16 or 28.

**An empty binary property returns an empty array, not `null`.** C++/CLI's
`ConvertToByteArray` takes `&data.bytes()[0]` — indexing element zero of a possibly empty
`std::vector`, which is undefined behaviour — and returns `nullptr` when that address comes
back null (`EventRecord.hpp:915-924`). So `TryGetBinary` could report success and hand back
a null array. The port returns a zero-length array. Consumers that null-check the result of
a successful `TryGetBinary` will stop taking that branch.

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

**No `EventRecordRef` accessor throws.** C++/CLI exposes three forms per type — `Get(name)`,
`Get(name, defaultValue)` and `TryGet(name, out value)`. The ref surface exposes the latter
two, uniformly, for every type it supports. The throwing form is dropped because a missing
property is an ordinary condition on a per-event path rather than an exceptional one, and
because an escaping handler exception now stops the trace, which would make a single mistyped
property name fatal to the session. The default-value form covers what the throwing form was
wanted for — `record.GetUnicodeString(name, default).SequenceEqual(other)` is a single
expression — while `TryGet*` remains the only form that separates absent from empty, since a
returned `ReadOnlySpan<char>` cannot express absence. `IEventRecord` keeps all three forms.

### Schema resolution failures are reported once, on the provider

An event whose schema cannot be resolved is reported through `Provider.OnError` and nothing
downstream of it runs — neither the provider's own event surfaces nor any of its filters.
`OnMetadata` is unaffected: it fires first, before anything resolves a schema, so a consumer
that only subscribes `OnMetadata` never pays for resolution and never sees an error for an
event no schema can describe.

The rule, end to end:

| Subscribed | Resolves a schema | On failure |
| --- | --- | --- |
| `OnMetadata` only | no | nothing; `OnMetadata` still fires |
| `OnEvent` / `OnEventRef`, or any filter | yes | one `Provider.OnError`; handlers and filters skipped |

krabs reports the same failure in a different place. Its predicates construct
`krabs::schema` outside their own `try` (`krabs/filtering/predicates.hpp:134`), so an
unresolvable schema throws past the predicate into each filter's `try/catch`
(`krabs/filtering/event_filter.hpp:214`), which reports it to *that filter's* error
callbacks. The provider's own error callback is a separate list and is never reached. The
practical consequences are that an undecodable event raises one error per filter rather than
one per event, and that a provider with only filters attached — the common shape — reports
nothing at all to `Provider.OnError`.

That last point is what motivated the change. HostIDS subscribes `OnError` only on providers
(`BaseEtwUserTraceContext.Enable`) while attaching its handlers to filters, so under krabs'
placement its ETW schema-error telemetry covers only the producers that use a provider-level
callback. Reporting on the provider puts the error where consumers actually attach.

`EventFilter.OnError` is retained and still raised when a filter is driven directly rather
than through a provider, as `Proxy(EventFilter)` does — there is nothing above the filter to
resolve or report in that configuration, and `describe_OnError.schema_not_found_should_raise_onerror_on_event_filter`
covers it.

A predicate that names a property the schema does not contain is a separate case and is
**not** an error in either implementation: krabs catches it inside the predicate and returns
`false` (`predicates.hpp:140-143`), and the port's accessors return `false` the same way. The
event is treated as a non-match and nothing is reported. Surfacing that as an error is
tracked separately; it would need a tri-state predicate result to distinguish "did not match"
from "could not be evaluated".

### A handler exception stops the trace and is reported

An exception thrown by a consumer's event handler cannot be allowed to unwind out of
`TraceCallbacks.Dispatch` — the frame above it is native `ProcessTrace`, and a managed
exception crossing that boundary is undefined behaviour rather than a clean crash. The catch
is therefore mandatory. What the port does with the caught exception is the part that had to
be chosen.

C++/CLI has no such catch. `base_provider::on_event` catches only `could_not_find_schema`
(`krabs/provider.hpp:485-505`) and `ExecuteAndConvertExceptions` catches only the eight krabs
C++ exception types (`Errors.hpp:69-101`), so a managed handler exception matches neither: it
unwinds the native `ProcessTrace` frames and leaves `UserTrace::Start()`. The session is gone
and the caller is told, loudly.

An intermediate revision of the port caught the exception, stored it in a `LastException`
field nobody read, and carried on. That is not availability — `EventsHandled` is incremented
before routing, so every counter a consumer polls keeps climbing while the module delivers
nothing, indefinitely and across restarts. Silence was the defect, not the catch.

The port now reproduces the C++/CLI outcome without the undefined behaviour:

| | C++/CLI | Port |
| --- | --- | --- |
| Exception leaves `Start()` | yes, by unwinding native frames | yes, rethrown after `ProcessTrace` returns |
| Original stack preserved | yes | yes, via `ExceptionDispatchInfo` |
| Session torn down | yes | yes, `CloseTrace` from the callback thread |
| Reported before the throw | no | `Provider.OnUnhandledException` and `UserTrace.DefaultUnhandledException` |
| Counted | no | `TraceStats.UnhandledExceptions` |
| Opt-out | no | `StopOnHandlerException = false` |

The first exception is captured with `ExceptionDispatchInfo`, further dispatch is
short-circuited, `Stop()` is called from the callback thread — safe because `Dispose` waits
outside `_gate` (`UserTrace.cs:897-901`), so nothing holds the lock the callback would need —
and `ProcessTrace` returns `ERROR_CANCELLED`, which `Start()` already treated as a clean stop.
`Start()` then rethrows. Both flags are per-run state and are cleared inside `Start()` under
`_gate`, so a trace stopped this way can be restarted.

Setting `StopOnHandlerException = false` keeps the trace running and still reports and counts,
which is the behaviour a consumer wants when one noisy provider must not take down the others.
No implementation has ever offered that, so it is additive rather than divergent.

Attribution to a provider runs on the exception path only, by re-deriving the match with the
same `TryGetRoutingId` helper the hot path uses. Nothing is stored per event to make it
possible. A provider set mutated concurrently could in principle misattribute a diagnostic,
which is the whole cost of the choice.

`Testing.Proxy.PushEvent` routes through the same `HandleDispatchException`, so the synthetic
path and the real callback agree, and then rethrows — which the real callback cannot do. A
test whose handler throws by accident fails rather than running green.

### Public surface that was removed

`MIGRATION.md` lists what was removed and what replaces it. The rationale, in each case,
is that nothing in the known consumer set used it:

| Removed | Reason |
| --- | --- |
| `EventRecord`, `EventRecordMetadata` classes | The port's adapter is reused and mutated per event; naming it publicly makes "hold it past the callback" look supported. C++/CLI also exposed `protected` `_EVENT_HEADER*` / `_EVENT_RECORD*` fields with no C# equivalent. |
| `PropertyEnumerable`, `PropertyEnumerator` | Allocates a `Property` per property; unused. |
| `IDisposable` on `Predicate`, `Property`, `KernelProvider`, `RawProvider`, `Provider`, `EventFilter` | These held a `NativePtr<T>` in C++/CLI — directly, or via a member that did — so the compiler gave each an implicit destructor and disposal freed C-runtime heap. The port's equivalents are plain managed objects with nothing to release; an empty `Dispose` would imply ownership that does not exist. |
| `IUserTrace.Enable(RawProvider)` | `RawProvider` is `[Obsolete]` in both implementations; the replacement is `Provider.OnMetadata`. |
| `Property.Type`, 3-argument `Property` ctor, `OutType` as `int` | The port exposes `InType`/`OutType`/`Length` as `uint`. Unused. |
| `EventHeaderProperty.LEGACY_EVENTLOG`, `FORWARDED_XML` | Renamed to `LegacyEventLog`, `ForwardedXML`. |
| `EventTraceProperties` public fields | Now properties. Object-initializer syntax is unaffected; only `ref`/`out` use breaks. |
| `GetSecurityIdentifier`, `TryGetSecurityIdentifier` | Declared on the concrete C++/CLI `EventRecord` (`EventRecord.hpp:347-382`), not on `IEventRecord`, so only consumers holding the concrete type were affected — and that type is removed anyway. The port has **no** way to read a SID property: `EventRecordRef` has no accessor and neither does the compat adapter. `RecordBuilder` can still *write* one. This is a genuine capability gap, not just a rename. |
| `GetPointer`, `TryGetPointer` returning `IntPtr^` | Same placement (`EventRecord.hpp:394-423`). The port keeps the capability on the ref surface as `EventRecordRef.TryGetPointer`, returning `ulong` rather than `IntPtr` so it does not box; the compat adapter has no equivalent. |

`IEventRecordError` *was* restored — `EventRecordError` implements it — because
`EventRecordErrorDelegate` is declared in terms of it and the interface is mocked by
consumers.

The public surface is differenced by reading metadata directly rather than by reflection,
because one side is a mixed-mode C++/CLI binary that cannot be loaded on .NET. That differ
is kept out of tree; it does not compare custom attributes, so `[Obsolete]` differences are
invisible to it.

### Composite predicates evaluate the cheaper side first

krabs' `and_filter` / `or_filter` evaluate strictly left to right — `t1_ && t2_` in
`predicates.hpp`. The port's `AndPredicate` / `OrPredicate` constructors instead order the
two operands by `PredicateTier`, so a predicate that only needs the header is always tested
before one that needs the decoded payload:

```csharp
// Cheapest side first. Ordering is decided once, here, not per event.
if (left.Tier <= right.Tier) { _first = left;  _second = right; }
else                         { _first = right; _second = left;  }
```

The reason is that the tiers are not equally priced: a header predicate reads a field that
is already in the buffer, while a payload predicate forces schema resolution and property
lookup. Testing `payloadPredicate && processIdPredicate` in source order pays the expensive
side on every event, including the ones the cheap side would have rejected outright.
Ordering is computed once at construction, not per event, so it costs nothing at dispatch.

The composite's own `Tier` is the *higher* of the two, so a filter containing any payload
predicate still resolves a schema — the reordering changes which side runs first, never
whether the filter is treated as a payload filter.

**This is observable**, because `Predicate` is public and abstract with a public `Test`, so
a consumer can write a predicate with a side effect. Such a predicate may now run in a
different order, or — where short-circuiting decides the result — not run at all when krabs
would have run it, and vice versa. None of the built-in predicates have side effects, so
this only affects consumer-authored ones. Predicates are expected to be pure; if you need
ordered evaluation with side effects, do the work in the event handler instead.

### Structs are not decoded

The port returns -1 from `OffsetResolver.SizeOf` for a property carrying
`PropertyStruct` rather than attempting to size it, which makes that property and
everything after it unreadable. This was scoped out of the initial milestone and has not
been revisited.

krabs does not decode structs either, and fails worse — see below. Nothing that worked
before stops working, but the failure mode changes from silent corruption to a visible
failure. Tracked internally.

## Things that look like divergences and are not

### The schema cache is unbounded in both implementations

Neither cache evicts. `krabs::schema_locator::cache_` and this port's `SchemaCache` are both
members of the trace, live as long as it does, and grow by one entry per distinct
`(provider, id, version, opcode, level, keyword, TraceLogging metadata, pointer width)`.
Failures are cached too, so an event with no schema also takes a slot.

Deliberately left that way, on measurement. For a manifest provider the entry count is
bounded by the manifest: the largest on a reference machine is Microsoft-Windows-Hyper-V-VMMS
at 3,332 events averaging 2.97 properties, which comes to roughly **1.6 MB** — and only for a
consumer that resolves every schema in it. Entries are also resolved lazily: a filter that
rejects on event id never touches the schema, because `EventIdIs` reads the header. Only a
filter that needs the schema — `EventNameIs`, a property predicate, or MOF/WPP routing —
populates the cache for events it is about to discard.

The genuinely unbounded case is a provider that generates event names or field layouts
dynamically, since a TraceLogging entry is keyed by its metadata. Compiled call sites are
finite, so this needs something like `EventSource.Write(userSuppliedName, …)`.

Eviction is not free here either: `SchemaEntry.Blob` is handed out as a raw pointer and read
throughout an event's dispatch, so evicting an in-use entry would be a use-after-free rather
than a cache miss.

The port's entries are larger than krabs' — about 386 bytes against 226 for a median
two-property event, because it also carries the precomputed `PropertyTable`. That was 626
bytes until the nine parallel arrays became one struct.

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

### SystemCallProvider matches no events in C++/CLI (fixed in the port, open in C++/CLI)

Tracked internally.

`SystemCallProvider` enables `EVENT_TRACE_FLAG_SYSTEMCALL` and then routes on the
`SystemTrace` GUID, `9e814aad-3204-11d2-9a82-006008a86939`. That is
`SystemTraceControlGuid`, the NT Kernel Logger's session control GUID: it goes in
`EVENT_TRACE_PROPERTIES.Wnode.Guid` to control the logger and appears on no event record.
SysCall enter and exit events are stamped with `PerfInfo`,
`ce1dbfb4-137e-4da6-87b0-3f59aa102cbc`, alongside DPC, ISR and profile events, whose
providers all use `PerfInfo` already. Kernel events route on the header GUID alone
(`krabs::details::kt::forward_events`, `TraceContext.Route` in the port), so the provider
enables the flag correctly, the session does the work, and the handler is never called.

Both implementations started here. Native krabs fixed it in 7e2dc32, whose commit message
reads "guid for system_call_provider should be PerfInfo not SystemTraceControl". The
C++/CLI wrapper was edited afterwards, in 396d8cc, and took that commit's new FileIo
providers -- and other `perf_info`-based providers -- but not the one-line fix.

The port uses `PerfInfo`. This is the only place it deliberately declines to reproduce the
wrapper, because reproducing the wrapper means the provider cannot work at all. A consumer
migrating off C++/CLI sees SysCall handlers begin to fire where they previously never did;
nothing that worked before changes. Coverage is
`KernelProviderTableTests.SystemCallProviderMatchesNativeKrabsRatherThanTheCppCliWrapper`,
which asserts the correct GUID and, as a regression guard, that it is not the wrapper's.

### krabs halves fixed-length Unicode strings (fixed in the port, open in C++/CLI)

Tracked internally.

`tdh.h` documents the two string in-types asymmetrically. For `TDH_INTYPE_UNICODESTRING`,
`epi.length` "contains number of WCHARs in the string"; for `TDH_INTYPE_ANSISTRING` it
"contains number of BYTEs". `krabs/size_provider.hpp` returns `propertyInfo.length`
unscaled for both, special-casing only `TDH_INTYPE_POINTER`, so a fixed-length Unicode
string is sized at half its true width. `parser::parse<std::wstring>` then divides the
byte count by `sizeof(wchar_t)`, so the string itself is truncated to half its characters
*and* every property after it in the event is read from the wrong offset.

The port scales by two for `UnicodeString` and leaves `AnsiString` unscaled
(`PropertySizer.cs`), on both the schema-length path and the `PropertyParamLength` path —
`tdh.h` calls the referenced property a WCHAR count too. Coverage is
`PropertySizerTests.FixedLengthUnicodeStringLengthIsACountOfWchars` and its ANSI
counterpart, which pin the asymmetry rather than the individual sizes.

This is a divergence from C++/CLI until the same fix lands there: a consumer migrating off
C++/CLI can see a different decoded value for such a property, and for anything after it.
Unlike the ANSI out-type defect below, the real-world exposure has not been measured — a
provider sweep for fixed-length Unicode string properties has not been run. Variable-length
and NUL-terminated strings are unaffected; both implementations scan the payload identically.

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

### A failed `Open` leaked the ETW session

`Open` creates the session with `StartTrace` and only then opens the consumer, sets the
handle and finally sets `_opened`. Anything that threw in between — a bad provider, a
consumer that could not be opened — left the session running in the kernel while the object
believed it had never opened. `Stop` early-returned on `!_opened`, so `Dispose` never issued
`ControlTrace(STOP)`, and it called `SuppressFinalize` on the way out, so the finalizer could
not clean up either. The session survived the process: machine-wide, invisible, and only
removable with `logman stop`.

`Stop` no longer looks at `_opened`. It stops whatever session exists, which is safe because
`ControlSession` ignores its return code and a session that was never created simply answers
`ERROR_WMI_INSTANCE_NOT_FOUND`.

Covered by `FailedOpenTeardownTests`, which forces the failed-open state and asserts that a
subsequent `ControlTrace(STOP)` reports 4201 — the session is already gone. Before the fix
the test reported 0: the session was still there.

### The finalizers took a static lock

`~UserTrace` and `~KernelTrace` called `ReleaseUnmanaged`, which calls
`TraceRegistry.Unregister`, which takes the static `Gate`. A finalizer that blocks on a lock
a mutator thread happens to hold stalls the whole finalizer queue, including finalizers that
free unmanaged memory for unrelated code. The comment on the finalizer already claimed
nothing was locked; it was wrong.

Both finalizers now call `StopSession` only — two native calls, no lock, no managed state.
The registry slot is left to be reclaimed by the weak reference it already holds.

### The offset resolver could outlive the record it was resolving against

`EventScratch.Resolve` called `_offsets.Begin(...)` only when a property table had been
found. On an event with no table the resolver kept the previous event's record and payload
pointers, both of which point into a buffer ETW reuses as soon as the callback returns. Any
later read through that resolver was a use-after-free. `Begin` is now unconditional.

### Extended data was read without checking the record was still valid

`EventRecordAdapter` guards `Ref` against use after `End()`, but `GetStackTrace`,
`TryGetContainerId` and `TryGetProcessStartKey` read `_record` directly. After `End()` that
is a dangling pointer, and the accessors returned empty or `false` rather than saying so.
All three now route through the same `ValidRecord` property `Ref` uses.

### A span was returned out of a `fixed` block

`SchemaCache.GetEventName` built its return value inside a `fixed` statement. That happens to
be safe here — the memory is native and not moved by the GC — but it is the exact shape of a
real bug and nothing in the signature says otherwise. Rewritten to slice the span it was
already handed.

### `Dispose` was not safe against a race with itself

`_disposed` was a plain `bool` read and written without synchronisation, so two threads
disposing the same trace could both run the teardown. Neither outcome was a crash — the
schema cache is guarded and the SafeHandles are idempotent — but a concurrent waiter could
see `_processingStopped` disposed underneath it. Now an `Interlocked.Exchange`.

### Deadlock analysis: no reachable deadlock

Recorded because the question is easier to answer once than to re-derive. The whole library
holds exactly two locks:

- `_gate`, one per `UserTrace`/`KernelTrace` instance.
- `TraceRegistry.Gate`, static.

`Gate` is a leaf. `Register`, `Unregister` and `InUse` touch only the slot array and the weak
references in it; none of them calls back into a trace, a provider or user code. The only
order that ever occurs is `_gate` then `Gate` — from `Open` and from `Dispose` — and since
`Gate` never reaches for `_gate`, an inversion is not expressible.

No lock is held across a wait. There are exactly two blocking waits in the library, both
`_processingStopped.Wait` inside `WaitForProcessingToStop`, and `Dispose` performs it between
its two `_gate` regions rather than inside one. This is the fix from *`Stop` freed state the
processing thread was still reading through*: the earlier code held `_gate` across a 30 second
wait while `Enable` needed the same lock, which deadlocked reproducibly at exactly 30.0 s.

User code is never called with a lock held. The live path — the ETW callback to
`TraceContext.OnEvent` to `Route` — takes no lock at all: `TraceRegistry.Get` is a pair of
volatile reads and the provider set is a single immutable `Routes` object read volatilely.
The testing `PushEvent` path takes `_gate` to publish providers but releases it before
dispatching. So a handler may call any method on any trace, including its own, without
risking an order it cannot see.

Disposing from inside a handler does not self-wait: `WaitForProcessingToStop` compares
against `_processingThread` and returns immediately on the processing thread.

Every wait is bounded (30 s) and `Stop` no longer waits at all, so a handler that blocks
forever costs a bounded delay rather than a hang. That last point matters to consumers that
call `Stop` while holding their own lock — HostIDS's `StopProcessTrace` does exactly this,
and its own comment records that it hit this class of bug independently.

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

### The property table cost more than the schema it annotated

`PropertyTable` held nine parallel arrays — name signatures, name offsets, name lengths,
in-types, out-types, flags, lengths, counts and fixed offsets. That is a reasonable shape for
a wide table and the wrong one here: the average event has 3.68 properties and the median has
2, measured across 50,058 event templates, so nine object headers dwarfed the data they
carried. A two-property table allocated 400 bytes to hold about 64 bytes of it, which made
each cache entry 2.7× the cost of krabs' — its entry is the TDH blob and a small key.

The per-property fields are now one 24-byte `PropertyInfo` struct, leaving two allocations
instead of nine. `NameSignatures` stays separate because a lookup scans only signatures and
benefits from them being contiguous.

| Properties | before | after |
| --- | --- | --- |
| 2 (median) | 400 B | 160 B |
| 4 (mean) | 448 B | 224 B |
| 8 (p90) | 576 B | 352 B |
| 22 (p99) | 1040 B | 800 B |

At the median a cache entry is now 386 bytes against krabs' ~226, rather than 626. The
sizing path also reads the flags, in-type, out-type, length and count of one property
together, which the old layout spread across five arrays.

The struct needs no padding, but only because its fields are ordered widest-first — there is
no `Pack` attribute, so a field added out of order would be padded rather than misaligned.
`PropertyInfoLayoutTests` pins the size, every field offset and the array stride so that
shows up as a failure instead of quietly growing every entry.

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

An entry that loses the comparison used to be *replaced* by the one that won, which was safe
— nothing can be misdecoded when the whole block is compared before an entry is returned —
but degenerate. Two blocks colliding on a 64-bit FNV hash under one descriptor would thrash:
a TDH lookup on every event, and a schema blob appended to the cache's allocation list on
every event, unbounded, for the life of the trace. Entries sharing a key are now chained
instead. The chain is only walked after an exact comparison has already failed, which is the
miss path either way, so the hot path is unchanged. `TwoShapesWhoseMetadataCollidesOnHashGetSeparateEntries`
covers it with a real FNV collision — two structurally valid metadata blocks found by a Brent
cycle search over the cache's own hash — rather than a mocked one.

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

Now only the values `FromFileTimeUtc` genuinely rejects are refused — negatives, and anything
above 2650467743999999999, which is `DateTime.MaxValue` expressed as ticks since 1601-01-01.
Refusing exactly those keeps `TryGetDateTime` non-throwing. Covered by
`FileTimeBoundaryTests`.

The upper bound was missed when this was first written: the guard read `fileTime < 0`, so a
FILETIME past 9999-12-31 still threw `ArgumentOutOfRangeException` out of the `TryGet` form
and, because that unwinds through the event handler, could stop the trace. Note the
`SYSTEMTIME` branch immediately below had always caught `ArgumentOutOfRangeException`, so the
two shapes disagreed about what an out-of-range time meant.

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
