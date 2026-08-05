# Pure .NET krabsetw — Design

Date: 2026-08-04
Status: Approved for implementation
Branch: `user/henribl/pure-dotnet`

## Goal

Replace the C++/CLI managed layer of krabsetw with a pure .NET implementation that:

1. Allocates **zero** bytes on the GC heap per event on its fast path.
2. Runs on **.NET Framework 4.6.2 / 4.8** and **.NET 10**.
3. Stays source-compatible with the krabsetw API surface consumed by HostSecurityService.
4. Is at least as fast as the current C++/CLI implementation.

Speed is the primary objective. Compatibility is the primary constraint.

## Motivation

The current implementation already avoids allocating the event object per event:
`CallbackBridge::WrapRecord` keeps one `EventRecord` instance and mutates it in place,
which is safe because `ProcessTrace` delivers events on the thread that called `Start()`.

The remaining per-event GC allocations come from the API contract, not the plumbing:

- `EventRecord::Name`, `ProviderName`, `TaskName`, `OpcodeName` each do `gcnew String(...)`.
- `GetUnicodeString` copies into a `std::wstring` and then allocates a `String^` — two copies.
- `CopyUserData()` allocates a `byte[]`.

So the win is not "stop allocating the record". The win is:

- eliminating the double copy on string property access,
- letting consumers compare property values without materializing a `string` at all,
- removing interface dispatch on the hot path,
- filtering earlier, so rejected events cost less,
- and shipping a single AnyCPU assembly with no mixed-mode DLL, no VC runtime, and one
  binary for .NET Framework and .NET.

## Non-goals

- Replacing the native `krabs` C++ headers. They stay; native consumers are unaffected.
- Supporting non-Windows platforms.
- Kernel trace parity in the first milestone (see Milestones).

## Architecture

Six layers, bottom up.

### 1. `Interop`

Blittable structs and raw P/Invoke. No marshalling directives, pointer-only signatures, so
the generated stubs stay trivial.

Structs: `EVENT_RECORD`, `EVENT_HEADER`, `EVENT_DESCRIPTOR`, `ETW_BUFFER_CONTEXT`,
`EVENT_HEADER_EXTENDED_DATA_ITEM`, `EVENT_TRACE_LOGFILE`, `EVENT_TRACE_PROPERTIES`,
`TRACE_EVENT_INFO`, `EVENT_PROPERTY_INFO`, `ENABLE_TRACE_PARAMETERS`,
`EVENT_FILTER_DESCRIPTOR`, `EVENT_FILTER_EVENT_ID`.

Imports: `StartTraceW`, `ControlTraceW`, `EnableTraceEx2`, `OpenTraceW`, `ProcessTrace`,
`CloseTrace` (advapi32); `TdhGetEventInformation` (tdh).

### 2. `SchemaCache`

Port of `krabs::schema_locator`. Composite key: provider GUID, event id, version, opcode,
level, keyword, and the TraceLogging event name when present (parsed from the
`EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL` extended-data blob, exactly as
`get_trace_logger_event_name` does today).

`TRACE_EVENT_INFO` blobs are stored in **unmanaged** memory (`Marshal.AllocHGlobal`):
off the GC heap, never relocated, no pinning required. Negative results (TDH failures) are
cached too, so a schemaless event is only looked up once.

Alongside each schema we precompute a **property table**: for each property, its name hash,
in/out type, length, count, and whether its offset is fixed or dynamic. Native krabs performs
a hinted linear name scan on every property lookup (see commits `27a7273`, `99869be`); we pay
that once per schema and index thereafter.

### 3. `EventRecordRef` (ref struct)

A view, never a container:

```csharp
public readonly ref struct EventRecordRef
{
    private readonly unsafe EVENT_RECORD* _record;
    private readonly unsafe TRACE_EVENT_INFO* _schema;
    private readonly PropertyTable _properties;
    private readonly OffsetScratch _offsets;
}
```

`UserData` is never copied. Property accessors return `ReadOnlySpan<byte>` /
`ReadOnlySpan<char>` pointing into the ETW-owned buffer. Dynamic-length properties still
require an in-order walk, so offsets resolve lazily against a memoized high-water mark rather
than being recomputed per access.

**Alignment:** ETW gives no alignment guarantee for property offsets. String properties are
resolved as `ReadOnlySpan<byte>` and compared with a UTF-16-aware byte comparison, taking the
`ReadOnlySpan<char>` fast path only when the offset is even.

### 4. `Filtering`

Predicates form a tree of sealed classes with `abstract bool Evaluate(ref EventRecordRef)`.
Ref structs are legal as parameters on all target TFMs. Comparisons run against the live
buffer (`span.StartsWith(literal, OrdinalIgnoreCase)`), materializing nothing.

Two optimizations, in order of value:

1. **Kernel-side event ID filtering (must preserve).** `ut.hpp` already pushes event-ID
   filters into ETW via `EVENT_FILTER_TYPE_EVENT_ID` on `EnableTraceEx2`, so non-matching
   events are never delivered to the callback at all. This is the single largest performance
   feature in the library and costs no managed work. It must be preserved exactly.
2. **Tiered predicate evaluation (new).** Predicates are classified at construction into
   header-only (event id, opcode, version, level, PID, provider GUID) and schema-requiring.
   Header-only predicates run *before* any schema-cache lookup or `TdhGetEventInformation`,
   so an event rejected on opcode never pays for schema resolution. Native krabs does not do
   this today.

### 5. Public API

Namespace `O365.Security.ETW`, preserving existing type and member names: `UserTrace`,
`KernelTrace`, `Provider`, `RawProvider`, `KernelProvider`, `EventFilter`, `Predicate`,
`EventTraceProperties`, `TraceStats`, `Property`, `IEventRecord`, `IEventRecordMetadata`,
`IEventRecordError`, `DecodingSource`, `EventHeaderProperty`, `TraceFlags`, and the
`Testing` triad (`RecordBuilder`, `SynthRecord`, `Proxy`).

Because the assembly reuses the namespace and type names, it **replaces** the existing
package rather than coexisting with it. Consumers swap one `PackageReference`.

### 6. Compatibility layer

`EventRecordAdapter : IEventRecord` is a reusable class holding the same raw pointers and
reconstructing the `EventRecordRef` on demand. One instance per trace context, mutated per
event — the same pattern as today's `WrapRecord`. HostSecurityService compiles unchanged.

It allocates only where the contract forces it (`GetUnicodeString` returns `string`,
`CopyUserData` returns `byte[]`). Numeric getters, `TryGetProcessStartKey`, and
`TryGetContainerId` are already allocation-free. The zero-alloc span API is opt-in, so call
sites migrate individually.

**Safety addition:** the adapter's pointers are valid only for the duration of the callback.
Today, stashing the record and reading it later silently returns corrupt data. A generation
counter is bumped per event; a stale access throws. Cost is one `int` comparison.

## Callback dispatch

### Two hops today

1. **ETW to krabs** (`etw.hpp`): `file.Context = &trace_` and `EventRecordCallback =
   trace_callback_thunk<T>`. The static thunk recovers the instance from
   `pRecord->UserContext`.
2. **krabs to managed** (`Callbacks.hpp`): `gcnew EventNativeDelegate(this, &CallbackBridge::
   EventNotification)` passed to `Marshal::GetFunctionPointerForDelegate`, producing a thunk
   with `this` baked in. `eventDelegateKeepAlive_` roots the delegate.

### In the port

`[UnmanagedCallersOnly]` requires a **static** method, so there is no bound receiver. The
receiver is recovered from `EVENT_RECORD.UserContext`, which echoes back
`EVENT_TRACE_LOGFILE.Context`. A managed object pointer cannot be stored there (the GC
relocates objects), so we store a small integer index into a static `TraceRegistry` array.
Dispatch is a plain array read: no `GCHandle.Target` deref, no dictionary, no allocation.

- **net10**: `[UnmanagedCallersOnly]` + `delegate* unmanaged<EVENT_RECORD*, void>`.
- **net462 / net48**: cached static delegate via `Marshal.GetFunctionPointerForDelegate`,
  rooted in a static field. Same static entry point, selected with `#if`.

Both TFMs share one dispatch path so the benchmark numbers are comparable.

### Per-event flow

1. Resolve trace context from `UserContext`.
2. Resolve provider by `ProviderId` (`Dictionary<Guid, ProviderState>`, allocation-free).
3. Fire `OnMetadata` subscribers — no schema required.
4. Evaluate header-only predicates. Reject early.
5. If a decoded event is needed, resolve the schema (cache, then TDH on miss).
6. Evaluate schema-requiring predicates.
7. Invoke the span callback, or hand the mutated `EventRecordAdapter` to
   `IEventRecordDelegate`.
8. If no provider matched, fall back to the trace-level `DefaultEvent` / `DefaultMetadata`.

### State ownership (fixes a latent race)

The offset scratch and the reusable adapter live on the **trace context**, not on the
provider. Today `Provider` owns its own `CallbackBridge`, so enabling one `Provider` instance
on two traces started on two threads silently shares mutable per-event state. Moving the state
to the trace context makes reuse correct by construction. No `[ThreadStatic]` is required,
because `ProcessTrace` uses one callback thread per trace.

## Error handling

A catch-all wraps the whole callback body; an exception escaping into `ProcessTrace` corrupts
the ETW loop. TDH failures and caught exceptions route to `OnError` using the same message
format as `krabs::get_status_and_record_context`, so existing log assertions keep passing.
Setup-time failures continue to throw the current exception types.

## Shutdown

`Stop()` from another thread issues `ControlTraceW(EVENT_TRACE_CONTROL_STOP)` then
`CloseTrace`, tolerating `ERROR_CTX_CLOSE_PENDING`; `Start()` returns once `ProcessTrace`
unwinds. `Dispose` stops the trace if running and frees every unmanaged schema blob.

## Testing

**Differential testing is the primary oracle.** `RecordBuilder` / `SynthRecord` / `Proxy`
push identical synthetic records through both implementations with no live session and no
admin rights. The corpus covers every in/out type pair (unicode / ansi / counted strings,
int8-64, uint8-64, binary, IP address, socket address, FILETIME, GUID, SID, bool, pointer),
fixed and dynamic lengths, arrays and structs, `PackIncomplete` truncation, and
TraceLogging / MOF / WPP decoding sources. Assertions cover values, thrown exception types,
and `OnError` message text.

Both assemblies export `O365.Security.ETW.UserTrace`, so the harness references the old one
through `extern alias` (`<Aliases>krabsNative</Aliases>`). The benchmark baseline uses the
same mechanism.

**Ported suite.** `tests/ManagedETWTests` (`describe_EventRecord`, `describe_InvalidParsing`,
`describe_OnError`, `describe_Proxy`, `describe_UserTrace`, plus `Events/` and `Filtering/`)
is the existing behavioural spec; it is ported and multi-targeted to net48 and net10.

**Acceptance gate.** Build HostSecurityService's `O365.Security.HostAgent.Modules` and
`HostAgentTests` against the new package and run its ETW test files **unmodified**. If
`TestEventRecord : IEventRecord` and `Mock<IEventRecordMetadata>` still compile and pass,
compatibility is demonstrated rather than asserted.

**Allocation assertions.** `GC.GetAllocatedBytesForCurrentThread()` delta must be exactly `0`
across N events on the span path (available on net462+). Enforced in CI.

**Live smoke test.** Synthetic records bypass `StartTrace` / `EnableTraceEx2` /
`ProcessTrace` — precisely the interop most likely to be wrong. A separate admin-only test
category runs a real `UserTrace` against a custom `EventSource`, asserting all events arrive
with correct values. It is also the only way to validate kernel-side event-ID filtering.

## Benchmarks

BenchmarkDotNet, `net48` and `net10.0-windows`, x64, one report. Three arms:

1. C++/CLI baseline, via `extern alias`.
2. New implementation through the `IEventRecord` compat path — **the fair comparison**.
3. New implementation through the `EventRecordRef` span path — the upside.

Micro cases over `SynthRecord` replay: schema-cache hit plus one `uint32` parse; unicode
string compare-only versus materialised; filter reject on event ID (header-only tier); filter
reject on string predicate; and one realistic ten-property network event modelled on the
HostSecurityService WinSock / ICMP converters. `[MemoryDiagnoser]` reports bytes/op with
ns/op.

**Macro benchmark**, because micro cases hide GC effects: a 60-second sustained run against a
self-firing `EventSource`, reporting events/sec, Gen0/Gen1 collections, and
`TraceStats.EventsLost`. Events lost is first-class — a consumer that is faster but drops
events is not faster.

## Kill criteria

If arm 2 does not reach parity with the C++/CLI baseline, the port should not ship, however
good arm 3 looks. HostSecurityService will not rewrite 121 call sites on day one, so the
compat path is the shipping path.

## Milestones

1. **Vertical slice.** `Interop`, `SchemaCache`, `EventRecordRef`, `UserTrace`, `Provider`,
   `EventFilter(eventId)`, the compat adapter, and the hottest accessors
   (`GetUnicodeString`, `GetUInt32/64`, `GetBinary`, `Name`, `ProcessId`). Plus
   `RecordBuilder` and the BenchmarkDotNet harness — numbers arrive in milestone 1, not last.
2. **Breadth.** Remaining accessors, `Predicate` combinators, string predicate families,
   `RawProvider`, `TraceStats`, `Property` enumeration, stack traces.
3. **Kernel traces.** `KernelTrace`, `KernelProvider`, PERFINFO mask support.
4. **Acceptance.** HostSecurityService builds and its ETW tests pass unmodified.

## Decisions log

- **Nested `global.json`.** The repository root pins SDK 8.0.100 with `latestFeature`, which
  cannot build net10. A nested `global.json` under the new subtree allows 10.x without
  disturbing the existing build.
- **Index over `GCHandle`** for `UserContext` routing: an array read beats a handle deref on
  the hot path.
- **Static entry point on both TFMs**, even though net48 could bind an instance delegate as
  C++/CLI does, so that dispatch is structurally identical across runtimes.
- **`ref struct` core with an interface adapter**, rather than either alone: `ref struct`
  cannot be boxed to `IEventRecord`, stored in a field, captured in a lambda, or mocked, and
  HostSecurityService does all four.
