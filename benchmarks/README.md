# Head-to-head benchmarks

`Shared\ProxyBenchmarks.cs` is compiled four times, giving a
{.NET Framework, .NET 10} × {C++/CLI, pure .NET} matrix:

| Project | Implementation | Runtime |
| --- | --- | --- |
| `Krabs.Benchmarks.Cli` | C++/CLI wrapper | net462 |
| `Krabs.Benchmarks.Pure` | pure .NET port | net48 |
| `Krabs.Benchmarks.CliCore` | C++/CLI wrapper | net10.0-windows |
| `Krabs.Benchmarks.PureCore` | pure .NET port | net10.0-windows |

Same source, same machine, both Release. That is what makes the comparison meaningful.

The C++/CLI toolset has no net10.0 target, so `Krabs.Benchmarks.CliCore` references the
net8.0 build and sets `RollForward=Major`. That runs the same assembly on the .NET 10
runtime, which is exactly what a consumer upgrading their host would get.

Events are driven through `Testing.Proxy` rather than a live ETW session. A real session
would mostly measure the kernel's buffering and flush cadence, which is identical for both
implementations and would swamp the difference being measured. What is measured is
everything from the trace's event callback inwards: provider matching, schema resolution,
predicate evaluation and property decoding.

## Running

Both C++/CLI wrappers must be built first — their vcxproj files need MSBuild.exe from
Visual Studio and cannot be imported by the dotnet CLI, so they are referenced as built
assemblies:

```powershell
msbuild krabs\krabs.sln /t:Microsoft_O365_Security_Native_ETW `
        /p:Configuration=Release /p:Platform=x64

msbuild Microsoft.O365.Security.Native.ETW.NetCore\Microsoft.O365.Security.Native.ETW.NetCore.vcxproj `
        /t:Restore`;Build /p:Configuration=Release /p:Platform=x64
```

Then run each arm in-process, so every cell is measured the same way:

```powershell
cd benchmarks\Krabs.Benchmarks.Cli
dotnet build -c Release; .\bin\Release\net462\Krabs.Benchmarks.Cli.exe -i

cd ..\Krabs.Benchmarks.Pure
dotnet build -c Release; .\bin\Release\net48\Krabs.Benchmarks.Pure.exe -i

cd ..\Krabs.Benchmarks.CliCore
dotnet build -c Release; dotnet .\bin\Release\net10.0-windows\Krabs.Benchmarks.CliCore.dll -i

cd ..\Krabs.Benchmarks.PureCore
dotnet build -c Release; dotnet .\bin\Release\net10.0-windows\Krabs.Benchmarks.PureCore.dll -i
```

`-i` is required for the net10.0-windows arms: BenchmarkDotNet's generated host project
targets plain `net10.0` and cannot reference a `net10.0-windows` assembly. It is used for
all four so the cells stay comparable.

Pass `--manual` to any of them for a plain stopwatch harness. It exists as a cross-check on
BenchmarkDotNet, and it reports a `sink/event` column.

## Results

All Release, x64, same machine, every cell run in-process (`-i`) and collected in a single
sitting. Times are per event.

Two event shapes are measured, because the shape dominates the result:

| Shape | Provider | Event | Payload |
| --- | --- | --- | --- |
| **DNS** | `Microsoft-Windows-DNS-Client` | 3008 v0 | 2 Unicode strings + 3 integers |
| **Network** | `Microsoft-Windows-Kernel-Network` | 11 v0 | 8 fixed-width integers |

Both are real providers with real schemas resolved through TDH, and both are shapes HostIDS
actually consumes. The Network shape is what `UserModeNetworkTraceProducer` reads, and it is
the interesting case for a zero-allocation port: an all-integer payload means even the
`IEventRecord` path allocates nothing, so the comparison is pure CPU. The DNS shape is what
`DnsResolutionProducer` reads, and it is the mixed case — two strings, so decoding it
allocates on the compat surface and not on the ref one.

The DNS event is modelled property-for-property on a live capture of the provider rather
than on its manifest, which ships no templates. Event 3008 carries five properties in this
order:

| # | Property | In-type | Read by HostIDS |
| ---: | --- | --- | :---: |
| 0 | `QueryName` | UnicodeString | yes |
| 1 | `QueryType` | UInt32 | yes |
| 2 | `QueryOptions` | UInt64 | |
| 3 | `QueryStatus` | UInt32 | |
| 4 | `QueryResults` | UnicodeString | yes |

The decode arms read exactly the three `DnsResolutionProducer.OnDnsResolutionEvent` reads,
which is deliberately the awkward set: `QueryResults` is the last property, so reaching it
walks the offsets of the four before it, including a variable-length string.

The values are anonymised, but sized from the capture. Across 789 real 3008 records
`QueryName` ran 11–76 characters (median 31, mean 30.6), and `QueryResults` was empty on 46%
of them and otherwise ran 10–390 characters (median 10, mean 27.1). The benchmark uses a
successful single-address A lookup — the modal non-empty case, and the only one that does
any work in `DnsResolutionProducer`, which returns early when `QueryResults` is blank.

`ref` is the `OnEventRef`/`EventRecordRef` path. The C++/CLI wrapper has no equivalent API,
so those columns are the port's alone.

### OnMetadata — header only, no schema resolved

The cheapest possible subscription: the provider matched, the header was read, and no
schema was resolved. This is the floor of the dispatch path.

| Shape | C++/CLI net462 | C++/CLI net10 | pure net48 | pure net10 |
| --- | ---: | ---: | ---: | ---: |
| DNS | 58.5 ns | 37.6 ns | 40.6 ns | **14.5 ns** |
| Network | 58.7 ns | 37.6 ns | 40.2 ns | **14.6 ns** |

1.4x faster on .NET Framework, 2.6x on .NET 10. The two shapes agree to within 0.3 ns on
every implementation, which is the expected result: a metadata subscription reads no
payload, so nothing here can depend on the shape.

An earlier revision of this file reported the port *losing* this row on .NET Framework, at
69.7 and 76.9 ns. Two of those three figures were wrong. The gap between the two shapes was
noise — the standard deviation on that run was 6.8 ns, and a metadata subscription reads no
payload at all, so a shape-dependent cost on it was never physically plausible. The absolute
number was real, and profiling found two causes: `EventRecordAdapter`'s accessors were past
RyuJIT's inlining budget because of an inline `throw` with string concatenation, and a
`try`/`finally` on the per-event path prevented both inlining and register allocation across
it. Both are fixed; the standard deviation is now 0.04 ns.


### Dispatch — provider matched, schema resolved, no property read

| Shape | C++/CLI net462 | C++/CLI net10 | pure net48 | pure net48 ref | pure net10 | pure net10 ref |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| DNS | 283.8 ns | 251.3 ns | 62.9 ns | 62.6 ns | 26.2 ns | **25.7 ns** |
| Network | 290.2 ns | 254.3 ns | 62.8 ns | 62.7 ns | 26.1 ns | **26.5 ns** |

4.5x faster on .NET Framework, 9.6x on .NET 10. `ref` and compat are the same here because
neither materialises a value.

### Decode — every property read

The DNS rows read the three properties HostIDS reads; the Network rows read four integers.

| Shape | C++/CLI net462 | C++/CLI net10 | pure net48 | pure net48 ref | pure net10 | pure net10 ref |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| DNS (2 strings, 1 int) | 1348.8 ns | 1194.3 ns | 451.8 ns | 382.6 ns | 204.5 ns | **154.9 ns** |
| Network (8 integers) | 942.5 ns | 791.6 ns | 240.2 ns | 195.2 ns | 116.4 ns | **90.2 ns** |

Allocation, same rows:

| Shape | C++/CLI net462 | C++/CLI net10 | pure net48 | pure net48 ref | pure net10 | pure net10 ref |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| DNS | 152 B | 152 B | 152 B | **0 B** | 152 B | **0 B** |
| Network | 0 B | 0 B | 0 B | **0 B** | 0 B | **0 B** |

The Network row allocates nothing anywhere: an all-integer payload returns value types, so
there is nothing for either implementation to put on the heap. Its speedup — 10.4x from
C++/CLI net462 to the port's net10 ref path — is entirely decode cost.

The DNS row is where the ref path earns its existence. Both implementations allocate an
identical 152 B through `IEventRecord`, because those bytes *are* the two `System.String`s
the contract returns and neither can avoid them. Only `EventRecordRef` removes them, which
is the difference between a busy trace producing garbage proportional to its event rate and
producing none. On the DNS shape that is 8.7x faster and 152 B/event cheaper than the
C++/CLI wrapper it replaces.

### Filters

`Filter` builds an `EventFilter` with a payload predicate; `Inline` is the same predicate
evaluated directly in an `OnEventRef` handler.

| Shape | | C++/CLI net462 | C++/CLI net10 | pure net48 | pure net48 ref | pure net10 | pure net10 ref |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| DNS | match | 579.3 ns | 509.0 ns | 207.5 ns | 207.8 ns | 69.9 ns | **70.9 ns** |
| DNS | reject | 293.4 ns | 265.4 ns | 192.7 ns | 193.4 ns | 67.7 ns | **67.3 ns** |
| Network | match | 545.0 ns | 480.3 ns | 106.4 ns | 106.4 ns | 50.8 ns | **50.6 ns** |
| Network | reject | 275.4 ns | 246.1 ns | 102.9 ns | 103.1 ns | 48.4 ns | **49.0 ns** |

Inline, port only:

| Shape | | pure net48 | pure net10 |
| --- | --- | ---: | ---: |
| DNS | match | 186.6 ns | 60.8 ns |
| DNS | reject | 176.5 ns | 60.3 ns |
| Network | match | 99.3 ns | 41.8 ns |
| Network | reject | 100.2 ns | 41.8 ns |

Inline is 0–13% faster than `EventFilter` — the cost of the filter object is the virtual
predicate call and the id check, and it is small.

**This understates `EventFilter` in production.** `Proxy` drives the dispatch path directly
and therefore cannot exercise **event-id pushdown**: when a provider carries only filters,
`UserTrace` collects their event ids and asks ETW to drop everything else in the kernel
(`UserTrace.cs:707-711`), so a non-matching event never reaches managed code at all. That
optimisation is disabled for the whole provider GUID as soon as any provider-level handler
is attached (`UserTrace.cs:795`) — which is exactly what the inline arms do. So the `reject`
rows above measure the *worst* case for `EventFilter` and the *best* case for inline; with
pushdown active a rejected event costs nothing rather than 48–193 ns. Prefer `EventFilter`.

This matters most for the DNS shape, because pushdown is precisely how HostIDS subscribes to
it: `DnsResolutionProducer` attaches a single `EventFilter(List<ushort>)` for events 1016,
3008 and 3020 and no provider-level handler, so every other event this provider emits is
dropped in the kernel. The filter rows here use a payload predicate instead, which is the
comparable measurement against the Network shape but a pessimistic model of that producer.

### Reading it

The port wins every cell on both runtimes, by 1.4x at the narrowest (metadata on .NET
Framework) and 10.4x at the widest (Network decode, C++/CLI net462 against the port's net10
ref path).

The port also gains more from the modern runtime than the C++/CLI wrapper does. Dispatch
goes 62.9 → 26.2 ns (2.4x) for the port against 283.8 → 251.3 ns (1.1x) for C++/CLI. That
asymmetry is expected: the C++/CLI hot path is native code the JIT never sees, so runtime
improvements largely bypass it, while the port is managed end to end and collects them in
full.

An earlier revision of this file claimed C++/CLI got *slower* on .NET 10 — dispatch 273.7 →
341.1 ns. Re-measuring the whole matrix in one sitting did not reproduce it: every C++/CLI
cell is faster on .NET 10, by 10–20%. The claim was an artefact of comparing arms collected
at different times, which is why the matrix is now regenerated as a set.

The narrowest margin is metadata on .NET Framework (40.2 vs 58.7 ns). It is also the row
most sensitive to the port's inlining, so treat it as the cell to re-measure first after any
change to `EventRecordAdapter` or `TraceContext.OnEvent`.

Both harnesses assert that the event handlers actually ran. This is not defensive
boilerplate: the first version of this benchmark reported the C++/CLI decode costing 1 ns
more than a no-op and allocating nothing, which looked like a spectacular result and was in
fact a measurement of nothing at all.

The cause was that `Proxy` does not keep the `UserTrace` it wraps alive. A trace held only
by a local was collected as soon as the constructor returned, after which `PushEvent`
silently delivered nothing. `ProxyBenchmarks` now roots its traces deliberately.

The lesson generalises: a benchmark that reports work as free is far more likely to be
broken than fast. Both harnesses now fail loudly instead.