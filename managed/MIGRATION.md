# Migrating to `Microsoft.O365.Security.ETW` 5.0

`Microsoft.O365.Security.ETW` is a pure .NET reimplementation of the C++/CLI wrapper that
shipped as `Microsoft.O365.Security.Native.ETW`, which was itself a thin layer over the
native `krabs` headers.

The port uses a **different package**, versioned **5.0.0**. The upstream C++/CLI baseline
is now **4.5.0**, not 4.4.x. The old id retained "Native" in the name, which no longer
describes anything about this implementation.

| | `Microsoft.O365.Security.Native.ETW` | `Microsoft.O365.Security.ETW` |
| --- | --- | --- |
| Package version | 4.5.0 baseline | 5.0.0 port |
| Assembly | `Microsoft.O365.Security.Native.ETW.dll` | `Microsoft.O365.Security.ETW.dll` |
| Namespace | `Microsoft.O365.Security.ETW` | *unchanged* |
| Target frameworks | net462, net8.0 | net462, net48, net8.0-windows, net10.0-windows |
| Architecture | x64 and ARM64 mixed-mode, under `runtimes/` | one AnyCPU assembly under `lib/` |

The namespace is unchanged, but that does **not** make this a source- or binary-compatible
package swap. Review the breaking-change checklists below and rebuild every consumer.

**Baseline versus pending fixes:** comparisons below use upstream C++/CLI 4.5.0 at
`d626e49`. A separate **pending native correctness backport** now fixes callback
invalidation, handler-exception containment, Unicode/ANSI decoding, FILETIME/IP/socket/binary
edge cases, SystemCall routing, filter-ID gating, provider/filter lifetime, synthetic-record
layout and TraceLogging hash-collision handling. These fixes are not assumed shipped in
existing 4.x packages. [PARITY.md](PARITY.md#comparison-baseline-and-pending-native-backport)
tracks the details and the differences deliberately retained after that backport.

The rest of this document lists every public-surface difference, followed by the two topics
most relevant after the swap: converting a hot handler to allocation-free access, and testing
handlers without a live trace.

---

## Breaking changes

The lists below distinguish **package/binary breaks**, **source/API breaks**, and
**behaviour breaks that still compile** when migrating from C++/CLI 4.5.0. Changes that
affect only earlier managed previews are listed separately. Pending native fixes do not
remove the need to review these lists when migrating an existing 4.x consumer.

### Package and binary compatibility

**Every consumer must be rebuilt.** The assembly name changes; an existing binary still
bound to the old assembly can fail to load or throw `MissingMethodException`.

| Breaking change | Required action |
| --- | --- |
| Package id changes from `Microsoft.O365.Security.Native.ETW` to `Microsoft.O365.Security.ETW` | Replace the `PackageReference` and rebuild all dependent assemblies. |
| Assembly name changes to `Microsoft.O365.Security.ETW.dll` | Update explicit assembly references, `Assembly.Load` calls, binding redirects and deployment rules naming the old DLL. The namespace remains unchanged. |

### Source/API breaking changes

These are **ten groups of source/API breaks**, not just behavioural differences.
Each row names the affected API and the migration action; details follow below.

| # | Breaking change | Required action |
| --- | --- | --- |
| 1 | `GetDateTime` returns `DateTime`; its default argument and `TryGetDateTime` out parameter also change from `ValueType` to `DateTime` | Update hand-written implementations, mock setups, default arguments and explicitly typed `out` variables. Use `TryGetDateTime` instead of a boxed-null sentinel. |
| 2 | `IDisposable` removed from `Predicate`, `Property`, `KernelProvider`, `RawProvider`, `Provider`, `EventFilter` | Remove `using` statements/declarations and `Dispose` calls for these six types. |
| 3 | `EventRecord` and `EventRecordMetadata` classes removed, including their concrete-only APIs | Use `IEventRecord` / `IEventRecordMetadata`. SID-property readers have **no replacement**; pointer-property reads move to `EventRecordRef.TryGetPointer`, returning `ulong`. See the capability gaps below. |
| 4 | `PropertyEnumerable` and `PropertyEnumerator` removed | Enumerate `IEventRecord.Properties` without naming the concrete iterator types. |
| 5 | `Property.Type` and the three-argument constructor removed; `OutType` changes from `int` to `uint` | Use `InType`; construct with `(name, inType, outType, length)`; update explicitly typed `OutType` consumers to `uint` or convert explicitly. |
| 6 | `EventTraceProperties` public fields become properties | Replace `ref`/`out` access with a local variable and assign the result back. Object initializers still work. |
| 7 | `EventHeaderProperty.LEGACY_EVENTLOG` / `FORWARDED_XML` renamed | Replace them with `LegacyEventLog` / `ForwardedXML`. |
| 8 | `IUserTrace.Enable(RawProvider)` removed from the interface | Migrate to `Provider.OnMetadata`; the concrete obsolete overload still exists. |
| 9 | `Testing.EventHeader` renamed to `Testing.EventHeaderView` | Update explicitly named types used with `RecordBuilder.Header`. |
| 10 | `Provider.EnableTraceLoggingFullSchemaHashing()` absent | Remove the opt-in call; the port always uses full TraceLogging metadata. |

### Behaviour breaking changes

**A successful build does not prove migration is complete.** Review these observable
changes even if no source/API row applies. Detailed examples and failure semantics are
in [Behaviour changes that still compile](#behaviour-changes-that-still-compile).

| Breaking change | Required action |
| --- | --- |
| Records are invalidated when the callback returns | Copy values inside the callback instead of retaining `IEventRecord` or borrowed data. Reads between callbacks now throw `InvalidOperationException`. |
| Failed `TryGet*` calls reset the out parameter | Do not rely on the variable retaining its previous value; keep the fallback separately. |
| Every user-provider registration sharing a GUID receives the event | Check for duplicate processing if registrations previously relied on first-match routing. Kernel routing stays first-match. |
| Composite predicates run cheaper operands first, not necessarily left to right | Keep predicates side-effect-free; move ordered work into the handler. |
| Unicode case-insensitive matching folds characters above U+007F | Review non-ASCII allow/deny-list expectations. Byte-oriented ANSI folding remains ASCII-only. |
| Schema failures move from each filter's `OnError` to the provider's `OnError` | Subscribe on the provider; expect one report per event rather than one per filter. A directly driven `Proxy(EventFilter)` still uses the filter's error event. |
| Handler exceptions are contained, reported, stop the session by default and are rethrown from `Start()` | Handle failure on the thread calling `Start()` and subscribe to reporting events. Set `StopOnHandlerException = false` only when continued dispatch is intended. |
| FILETIME, IP, socket and empty-binary edge cases change | Handle empty socket values as `null`, use `TryGet*` for malformed values, and expect a successful empty binary read to return an empty array, not `null`. See the conversion table below. |
| Fixed Unicode lengths, UTF8/JSON decoding and sized strings with embedded NULs are corrected | Recheck decoded values and remove workarounds for truncation, wrong encoding or displaced properties. |
| `SystemCallProvider` now routes on PerfInfo and receives events | Expect handlers that were previously silent to run. |
| Struct properties are rejected instead of being mis-sized | Treat the struct and following properties as unreadable; neither implementation provides struct decoding. |
| TraceLogging schema identity always uses the complete metadata | Expect same-named events with different layouts to resolve independently; test mixed emitter versions rather than relying on the first cached layout. |

### Additional breaks when updating an earlier managed preview

These are **preview-to-preview changes**, not additional differences from C++/CLI 4.5.0.

| Change | Required action |
| --- | --- |
| `UserTrace.DefaultUnhandledException` / `KernelTrace.DefaultUnhandledException` become events instead of settable delegate properties | Replace assignment with `+=` / `-=`; do not read the delegate. Each reporting subscriber is contained independently, so a throwing reporter cannot silence later subscribers or prevent stopping. |
| `KernelProvider.GroupMask` narrows from `ulong` to `uint` | Update preview-era callers to `uint`; high bits were previously discarded. This restores the C++/CLI signature. |
| `TraceStats.EventsHandled` / `EventsTotal` regain native counting semantics and event/buffer counts reset on `Open` | Count provider matches in your own handler; do not interpret trace totals as matched-event counts or lifetime totals. |
| Default buffering becomes `REAL_TIME_MODE | NO_PER_PROCESSOR_BUFFERING` | Set a nonzero `LogFileMode` explicitly if another buffering mode is required. |
| `Stop` no longer releases callback registrations or logger names; `Dispose` owns teardown | Dispose the trace. If shutdown requires no further handlers, wait for the blocking `Start()` call to return; `Stop()` is a signal, not a join. |

**Not an additional source break:** `TraceStats` is now a `readonly struct`, but the
C++/CLI fields were already `initonly` and its populated constructor was already internal.
Reading `QueryStats()` results and constructing `new TraceStats()` remain supported.

### Source/API details

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

**2. `IDisposable` is gone from six types.** `Predicate`, `Property`, `KernelProvider`,
`RawProvider`, `Provider` and `EventFilter` held a `NativePtr<T>` in C++/CLI — directly, or
via a member that did — so the compiler gave each an implicit destructor and disposal freed
C-runtime heap. The port's equivalents are plain managed objects with nothing to release, and
an empty `Dispose` would imply an ownership that does not exist. Remove the `using` blocks and
`Dispose` calls; a `using` statement on any of these no longer compiles.

`UserTrace`, `KernelTrace`, `Testing.RecordBuilder` and `Testing.SynthRecord` are unaffected
and remain disposable — each owns a trace handle, unmanaged buffers, or both.
`Testing.Proxy` *gained* `IDisposable`.

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

**10. Remove `Provider.EnableTraceLoggingFullSchemaHashing()` calls.** C++/CLI 4.5.0 makes
full-schema hashing opt-in per provider. The port always uses and compares the complete
declared TraceLogging metadata, so it has no opt-in method or opt-out. Extended-data padding
outside the declared metadata size is ignored by both implementations.

### Types that no longer exist

Items 3 and 4.

| # | Removed | Why |
| --- | --- | --- |
| 3 | `EventRecord`, `EventRecordMetadata` classes | The port's adapter is reused and mutated per event, so naming it publicly makes "hold it past the callback" look supported. C++/CLI also exposed protected `_EVENT_HEADER*` / `_EVENT_RECORD*` fields that have no C# equivalent. Use `IEventRecord` / `IEventRecordMetadata`; note the `DateTime` signature change above. |
| 4 | `PropertyEnumerable`, `PropertyEnumerator` | Allocated a `Property` per property. `IEventRecord.Properties` still works; only the concrete iterator types are gone. |

**Reading a SID property has no replacement.** `GetSecurityIdentifier` /
`TryGetSecurityIdentifier` were declared on the concrete `EventRecord`, which is gone, and
nothing in the port replaces them — neither `EventRecordRef` nor the compat adapter can read
a `Sid`-typed property. If you depend on this, say so; it is a capability gap rather than a
deliberate removal. `RecordBuilder.Sid` still exists for writing test records.

`GetPointer` / `TryGetPointer` survive as `EventRecordRef.TryGetPointer`, which returns
`ulong` rather than `IntPtr` so the value is not boxed. There is no compat equivalent.

`IEventRecordError` *was* kept — `EventRecordError` implements it — because
`EventRecordErrorDelegate` is declared in terms of it and consumers mock it.

### Behaviour changes that still compile

These details cover the behaviour checklist above and the preview-only runtime changes
identified separately. Unlike the source/API changes, they can affect code that builds
successfully.

**An `IEventRecord` is invalid once the handler returns.** C++/CLI reuses one record object
per bridge and only ever reassigns its `EVENT_RECORD*` (`EventRecordMetadata.hpp:26-41`,
`Callbacks.hpp:75-88`), so a handler that stashed the record kept reading it — first from
freed memory, then, once the next event arrived, that event's data, with no diagnostic
either way. The port reuses the object the same way, so nothing is allocated, but clears the
pointer on return: a read between callbacks throws `InvalidOperationException`.
The pending C++/CLI backport adds invalidation too, but throws `ObjectDisposedException`.
Neither reused wrapper is a snapshot: an alias can see the new event once a later callback
rebinds the object. Never retain the wrapper.

If you stored records to process later, copy what you need inside the handler instead:

```csharp
provider.OnEvent += record =>
{
    // was: _pending.Add(record);   // silently read the wrong event later
    _pending.Add(new MyEvent(record.ProcessId, record.GetUnicodeString("ImageName")));
};
```

**`TraceStats.EventsHandled` now counts every event, and `EventsTotal` includes lost
events.** The port previously reported `EventsHandled` as only the events some provider
claimed, and `EventsTotal` as the unclaimed-inclusive count with lost events omitted.
Neither matched krabs, which increments one counter before forwarding and derives
`eventsTotal = eventsHandled + EventsLost`. Both readings now match C++/CLI. If you were
using `EventsHandled` as "events my providers matched", that number is no longer available —
count them in your handler instead. The counters are also now reset by `Open`, as krabs
resets them in `start`/`open`/`process`, so a reopened trace no longer accumulates across
cycles.

**Composite predicates evaluate the cheaper side first.** `a && b` evaluates left to right
in krabs, but the port orders the two sides by tier, so a header predicate always runs
before a payload one regardless of how you wrote it. This is invisible for the built-in
predicates, which are pure. It is only observable if you subclass `Predicate` and give
`Test` a side effect — in which case the side effect may run in a different order, or be
short-circuited away entirely. Do side-effecting work in the event handler, not a predicate.

**Value conversions differ from the baseline at degenerate inputs.** The pending native
backport fixes these cases too; see `PARITY.md` for the rationale.

| Input | C++/CLI | Port |
| --- | --- | --- |
| FILETIME below zero or beyond year 9999 | `ArgumentOutOfRangeException` out of `GetDateTime` *and* `TryGetDateTime` | `TryGetDateTime` returns `false`; `GetDateTime` throws `ParserException`; default overload returns its default |
| Socket address whose length is not 16 or 28 | Sized from the address family, fixed 16/28 bytes copied out of a 128-byte buffer | Sized from the property, exactly its bytes copied |
| Empty binary property | `TryGetBinary` returns `true` with a `null` array | `TryGetBinary` returns `true` with a zero-length array |
| Present, zero-length socket address | May return uninitialised storage | `GetSocketAddress` returns `null`; `TryGetSocketAddress` returns `false` |

If you wrapped `TryGetDateTime` in a `try`, you no longer need to. If you null-checked the
array from a successful `TryGetBinary`, that branch is now dead.

`GetSocketAddress(string)` now has a nullable return annotation. Handle `null` when the
provider emits an empty address; missing, truncated, and one-byte values still throw.
`TryGetIPAddress` requires an IPv4/IPv6 TDH out-type and the corresponding 4/16-byte width,
rather than treating any property of either size as an address.

Throwing compat getters now explain whether a property is absent, its offset walk stalled,
its length could not be resolved, its bytes exceed the payload, it is present but empty,
or the requested type rejected it. Use `TryGet*` for control flow rather than depending on
the exact `ParserException` message.

**String and kernel-routing fixes may expose previously wrong values.** Fixed Unicode
lengths count WCHARs, not bytes; UTF8/JSON ANSI out-types use UTF-8 in getters, predicates
and builders; explicitly sized strings preserve embedded NULs; and `SystemCallProvider`
routes on PerfInfo so its handlers actually fire. These also have pending native fixes.
XML remains on the machine ANSI code page; neither implementation parses its encoding
declaration.

**User-trace registrations sharing a GUID each receive the event.** Their keyword masks
were already merged for ETW enablement, but earlier managed previews dispatched only to
the first registration. Each registration now runs its own handlers and filters in
registration order. This deliberately differs from native krabs' first-match routing;
kernel-trace routing is unchanged. An exception aborts the remaining registrations for
that event and is attributed to the registration that threw.

**Default trace buffering matches native krabs.** With `LogFileMode == 0`, user and kernel
traces use `REAL_TIME_MODE | NO_PER_PROCESSOR_BUFFERING`, avoiding a separate buffer pool
per processor. An explicit nonzero mode is used as supplied; kernel traces additionally
require `SYSTEM_LOGGER_MODE` in either case.

**Schema resolution failures now surface on `Provider.OnError`, not on each filter.** In
C++/CLI an event whose schema cannot be resolved raises `OnError` on every filter attached to
the provider, and never raises the provider's own `OnError`. The port raises
`Provider.OnError` once and skips the provider's handlers and all of its filters.

```csharp
provider.OnError += e => Log(e.Message);   // C++/CLI: never fires for a filtered provider
filter.OnError   += e => Log(e.Message);   // C++/CLI: fires, once per filter per event
```

If you subscribed `EventFilter.OnError` to learn that events were undecodable, move that
subscription to the provider. If you already subscribe `Provider.OnError`, you will begin
seeing errors from filtered providers that were previously silent — one per event rather than
one per filter. `EventFilter.OnError` still fires when a filter is driven directly through
`Proxy(EventFilter)`, where there is no provider above it. See *Error handling flow, before
and after* below for how this fits with the other two failure kinds.

Unchanged: `OnMetadata` fires before anything resolves a schema, so a metadata-only consumer
neither pays for resolution nor sees these errors. Also unchanged: a predicate naming a
property the schema does not contain is a non-match, not an error, in both implementations.

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

**Struct-typed properties are not decoded.** A property carrying `PropertyStruct`, and
everything after it in the payload, is unreadable. krabs does not decode structs either and
can mis-size the union fields in the baseline. The pending native backport rejects structs
explicitly instead. Neither implementation gains struct decoding.

**A handler exception stops the trace and leaves `Start()`.** This restores the C++/CLI
outcome — there, a managed exception thrown in a handler unwinds the native `ProcessTrace`
frames and exits `Start()`, because neither `base_provider::on_event` nor
`ExecuteAndConvertExceptions` catches anything that matches it. An intermediate revision of
the port caught it and continued silently, which left a consumer polling healthy-looking
counters on a trace that was delivering nothing. The port now captures the first exception,
reports it, stops the session, and rethrows it — with its original stack — out of `Start()`.
The old native unwind did not guarantee session teardown. The pending native backport
also contains exceptions and stops safely before rethrowing, but does not add the reporting
events, counter or opt-out shown below.

```csharp
provider.OnUnhandledException += e => Log(e.Exception, e.Record.ProviderId, e.Stopping);
trace.DefaultUnhandledException += e => Log(e.Exception);   // also fires for unattributed ones

var stats = trace.QueryStats();
Console.WriteLine(stats.UnhandledExceptions);
```

If one noisy provider must not take down the rest, opt out — the exception is still reported
and still counted, and dispatch continues:

```csharp
trace.StopOnHandlerException = false;
```

A trace stopped this way can be restarted; the state is cleared by `Start()`. See *Error
handling flow, before and after* below for the exact ordering and how this relates to decode
failures.

**`Stop` no longer releases the trace's resources — `Dispose` does.** `Stop` signals the
session to stop and returns, which is what the C++/CLI `Stop` does too. What changed is that
the port used to release its callback registration and logger name inside `Stop`; it now
holds them until `Dispose`, because `ProcessTrace` goes on draining buffered events after
`CloseTrace` and is still reading through both. `Dispose` waits for that to finish (30
seconds) and then releases.

The consequence is that a caller who needs "no handler will run again" — before tearing down
whatever its handlers touch — must wait for its `Start` call to return. `Stop` alone does not
promise it, and never did in C++/CLI either.

Disposing is still the right thing to do, but it is no longer the only thing standing between
a consumer and a leak: every type that owns unmanaged memory has a finalizer as a last
resort. `UserTrace` and `KernelTrace` stop their session and release their registration and
logger name; `SchemaCache` frees its schema blobs; `SynthRecord` frees its record and payload.
A finalizer runs at a time nobody chose, so an ETW session can outlive its owner by a while —
dispose your traces — but an abandoned one no longer leaks for the life of the process.

**Not a behaviour change: nullable reference annotations.** The public surface is annotated,
so a project that has opted into nullable reference types now receives accurate diagnostics
where it previously received none. `TryGet*` carries `[MaybeNullWhen(false)]`, which is what
allows `if (record.TryGetUnicodeString(name, out var s))` to narrow `s` to non-null in the
true branch. Annotations are metadata only and cannot break a compile that was not already
opted in.

### Error handling flow, before and after

Three different things can go wrong while a trace is running, and they were previously
reported in three inconsistent ways. This is the whole picture in one place.

| What failed | C++/CLI | Port |
| --- | --- | --- |
| The library cannot decode an event | `EventFilter.OnError`, once **per filter**. `Provider.OnError` never fires for a filtered provider | `Provider.OnError`, once **per event**. Filters and handlers are skipped |
| Your handler throws | Nothing fires. The exception unwinds native `ProcessTrace` and leaves `Start()` | `Provider.OnUnhandledException`, then `DefaultUnhandledException`, then the trace stops and `Start()` rethrows it |
| `Open`/`Start`/`Enable` fails | An exception out of the call | `TraceException` with a `Status`, out of the same call |

**Before — what a consumer had to write:**

```csharp
// Decode failures: had to be hung off every filter, because the provider never saw them.
filter.OnError += e => Log(e.Message);
provider.AddFilter(filter);

// Handler failures: nothing to subscribe. The only signal was Start() throwing,
// on the thread calling Start(). The old unwind did not guarantee session teardown.
try
{
    trace.Start();
}
catch (Exception ex)
{
    Log(ex);          // could be a trace failure or any handler's bug -- indistinguishable
}
```

**After:**

```csharp
// Decode failures: one subscription, on the provider, covering filtered providers too.
provider.OnError += e => Log(e.Message);

// Handler failures: reported where the fault is, before the trace unwinds.
provider.OnUnhandledException += e => Log(e.Exception, e.Record.ProviderId, e.Record.Id);
trace.DefaultUnhandledException += e => Log(e.Exception);

try
{
    trace.Start();
}
catch (TraceException ex)
{
    Log(ex.Status);   // the session itself failed
}
catch (Exception ex)
{
    Log(ex);          // a handler threw; already reported above, with the event that caused it
}
```

The ordering guarantees, for the handler-exception path:

1. The exception is counted — `QueryStats().UnhandledExceptions`.
2. `Stopping` is set, so no further event is dispatched.
3. `Provider.OnUnhandledException` fires for the provider whose dispatch threw. If **that**
   reporter throws too, it is recorded without silencing later subscribers or step 4.
4. `DefaultUnhandledException` fires on the trace, for every exception — including ones with
   no provider to attribute, such as a throw from the trace-level default handler.
5. The session is stopped even if a reporting subscriber threw.
6. `Start()` rethrows the **first** exception, with its original stack.

Set `trace.StopOnHandlerException = false` to keep steps 1, 3 and 4 and drop 2, 5 and 6: the
exception is still counted and still reported, with `e.Stopping` false, and dispatch carries
on. That is what you want when one provider's handler must not take down the others. Neither
implementation offered it before.

Two things worth knowing. `OnMetadata` is **not** gated on a schema, so a metadata-only
consumer never triggers a decode failure and never pays for resolution. And
`EventFilter.OnError` still exists and still fires when a filter is driven directly through
`Proxy(EventFilter)`, where there is no provider above it to report to.

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
- Handler-exception reporting — `Provider.OnUnhandledException` /
  `KernelProvider.OnUnhandledException`, `UserTrace.DefaultUnhandledException` /
  `KernelTrace.DefaultUnhandledException`, the `IEventRecordException` they carry,
  `TraceStats.UnhandledExceptions`, and `StopOnHandlerException`. See above.
- `EventRecordRef.TryGetProcessStartKey` and `TryGetContainerId` read extended data without
  resolving a schema or materializing an adapter.
- Synthetic-record helpers — `RecordBuilder.Header.ProcessId` sets the event header's
  process identity; `EventSchema.IPAddress` declares IPv4/IPv6 out-types for address tests.

---

## Converting a handler to zero-allocation comparison

String and binary getters on `IEventRecord` materialise values from the ETW buffer;
header and scalar reads do not inherently allocate. The adapter object itself is reused
for the life of the trace. Moving string comparisons to spans avoids allocating values
that a handler only inspects and discards.

`EventRecordRef` hands back `ReadOnlySpan<T>` views straight into the buffer instead. It is a
`ref struct` with no record interface; reaching it means subscribing
`OnEventRef` rather than `OnEvent`.

| | Callback | Record type | Allocates |
| --- | --- | --- | --- |
| Compat | `OnEvent` / `DefaultEvent` | `IEventRecord` | on materialising strings, arrays and address objects |
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

Payload accessors on `EventRecordRef` take the property name as a `ReadOnlySpan<char>`.
Strings convert implicitly to that type on older compilers too; this does not require
C# 14. Either spelling works:

```csharp
record.TryGetUnicodeString("ImageName".AsSpan(), out var image);  // explicit span
record.TryGetUnicodeString("ImageName", out var image);           // implicit string-to-span conversion
```

The explicit `.AsSpan()` form costs nothing at run time and makes span comparisons
unambiguous; most examples below use it for clarity.

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

- **`GetAnsiString`.** Transcoding from the provider's code page is what forces the
  allocation. `TryGetAnsiStringBytes` returns the raw `ReadOnlySpan<byte>` instead. Note there
  is currently no built-in way to compare those bytes against a `string` literal. The code
  page is the machine's ANSI one unless the property's out-type says otherwise: `win:UTF8`
  and `win:Json` properties are decoded, compared and built as UTF-8. Raw bytes are returned
  untranscoded either way, so a caller comparing them itself has to encode its comparison
  value to match.
- **IP-address and socket-address accessors**, because `IPAddress` and `SocketAddress` are
  classes.
- **`Properties` enumeration.**
- **Throwing `Get(name)` payload accessors.** Where C++/CLI offers three forms per type,
  the ref surface offers `TryGet*` and default-returning forms for ordinary lookup failures:

  ```csharp
  bool TryGetUInt32(ReadOnlySpan<char> name, out uint value);        // distinguishes absent
  uint GetUInt32(ReadOnlySpan<char> name, uint defaultValue);        // substitutes instead
  ```

  Debug builds still throw `TypeMismatchAssert` for a numeric TDH in-type mismatch,
  matching native krabs; the `TryGet*` form does not suppress that assertion.

  A missing property is an ordinary condition on a hot path, not an exceptional one, and the
  ref surface exists to avoid per-event costs; a throwing accessor invites exceptions as
  control flow, and — since the port stops the trace when a handler exception escapes — makes
  one mistyped property name fatal to the session.

  The default-value form is what keeps a comparison readable in a single expression, which is
  the reason a throwing form is usually wanted:

  ```csharp
  if (record.GetUnicodeString("QueryName".AsSpan(), default)
            .SequenceEqual("host.example.com".AsSpan()))
  ```

  Use the `TryGet*` form wherever absent has to be distinguished from empty. A returned
  `ReadOnlySpan<char>` cannot express "absent" — an empty span is exactly what a genuinely
  empty string property yields — so `TryGet*` is the only form that separates the two.
  `IEventRecord` keeps all three forms, including the throwing one, for every type.

---

## Testing handlers

Tests may keep mocking `IEventRecord`. Ordinary `Mock<IEventRecord>` and
`It.IsAny<IEventRecord>()` usages are unchanged, but `DateTime` setups and hand-written
implementations must adopt the new signatures described above.

Tests covering a handler moved to `OnEventRef` do not. `EventRecordRef` is a `ref struct`, and
a mocking framework cannot represent one:

- ordinary mocking APIs do not accept ref-struct type arguments, so `Mock<EventRecordRef>`
  and `It.IsAny<EventRecordRef>()` do not compile. C# 13's `allows ref struct` support on
  compatible runtimes does not remove a mocking API's class constraints or boxing needs;
- it cannot appear in an expression tree, so `Setup` on a member that takes or returns one
  fails (CS8640, CS9244);
- it cannot be boxed, stored in a class field, captured in a lambda, or returned from an `async`
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

Five constraints on `RecordBuilder` are easily overlooked:

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
  The same applies to `AddBinary` where the template fixes the width: a `win:Binary` value
  carries no length of its own, so the reader takes the width from the schema and ignores
  the bytes, and supplying a different number of them would shift every later property.
- **A record's payload must not exceed 65535 bytes.** `EVENT_RECORD.UserDataLength` is a `USHORT`,
  so `Pack()` rejects anything larger rather than letting the length wrap. Real events are
  bounded the same way; a fixture that hits this is usually padding a string far past what
  the provider would emit.

Assertions inside a ref handler carry one further constraint: the record cannot be captured,
so nothing about it can be asserted through a lambda-taking overload such as `Assert.Throws`.
Assert inline instead. Assert a missing property on the `TryGet*` result or returned
default rather than on an exception:

```csharp
Assert.False(record.TryGetUnicodeString("Missing", out var value));
Assert.True(record.GetUnicodeString("Missing", "fallback").SequenceEqual("fallback".AsSpan()));
```

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
earlier one, as `length="PathLength"` does in a manifest. `Utf8String` and `JsonString`
declare an 8-bit string carrying UTF-8, which is `win:AnsiString` with an out-type of
`win:UTF8` or `win:Json` in a manifest. `Named` supplies the value `EventRecordRef.Name`
reports; the provider name passed to `Create` supplies `ProviderName`.

Two points are worth keeping in mind:

- **A declaration is only as accurate as whoever wrote it.** It records what the test believes
  the event looks like, so a declaration that has drifted from the real manifest yields a
  passing test against an event shape that is never emitted. Prefer a real in-box provider
  where one exists, and keep the declaration next to the template it mirrors.
- **The scope is the execution context, not the process.** `AsyncLocal` declarations flow
  with that context, including into `Task.Run`; unrelated test contexts do not see them.
  Disposing the value returned by `Use` restores the previous scope. Declarations are a test
  override, not a way to register a production provider. The cache consults them only on a
  miss: existing entries are not overridden, and a resolved entry survives scope disposal.
  Use a fresh trace/proxy when changing declarations for the same event.

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
