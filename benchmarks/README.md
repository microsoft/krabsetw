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
| **PowerShell** | `Microsoft-Windows-PowerShell` | 7937 v1 | 3 Unicode strings |
| **Network** | `Microsoft-Windows-Kernel-Network` | 11 v0 | 8 fixed-width integers |

Both are real providers with real schemas resolved through TDH. The Network shape is the
one HostIDS's `UserModeNetworkTraceProducer` consumes, and it is the interesting case for a
zero-allocation port: an all-integer payload means even the `IEventRecord` path allocates
nothing, so the comparison is pure CPU.

`ref` is the `OnEventRef`/`EventRecordRef` path. The C++/CLI wrapper has no equivalent API,
so those columns are the port's alone.

### OnMetadata — header only, no schema resolved

The cheapest possible subscription: the provider matched, the header was read, and no
schema was resolved. This is the floor of the dispatch path.

| Shape | C++/CLI net462 | C++/CLI net10 | pure net48 | pure net10 |
| --- | ---: | ---: | ---: | ---: |
| PowerShell | 57.7 ns | 54.8 ns | 69.7 ns | **15.0 ns** |
| Network | 57.7 ns | 55.1 ns | 76.9 ns | **14.2 ns** |

**The port is slower than C++/CLI here on .NET Framework** — 69.7 vs 57.7 ns — and 3.8x
faster on .NET 10. This is the one row where .NET Framework loses, and it is the honest
shape of the trade: the metadata path is so short that it is dominated by the managed
callback and header marshalling, which the older JIT does not optimise well. Everything
below this line, the port wins on both runtimes.

### Dispatch — provider matched, schema resolved, no property read

| Shape | C++/CLI net462 | C++/CLI net10 | pure net48 | pure net48 ref | pure net10 | pure net10 ref |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| PowerShell | 273.7 ns | 341.1 ns | 87.1 ns | 86.5 ns | 34.4 ns | **32.6 ns** |
| Network | 290.5 ns | 345.2 ns | 91.3 ns | 93.0 ns | 41.0 ns | **40.6 ns** |

3.1x faster on .NET Framework, 8.4x on .NET 10. `ref` and compat are the same here because
neither materialises a value.

### Decode — every property read

| Shape | C++/CLI net462 | C++/CLI net10 | pure net48 | pure net48 ref | pure net10 | pure net10 ref |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| PowerShell (3 strings) | 1481.6 ns | 1482.6 ns | 495.0 ns | 416.2 ns | 280.7 ns | **198.7 ns** |
| Network (8 integers) | 930.7 ns | 967.6 ns | 344.5 ns | 286.2 ns | 166.7 ns | **119.3 ns** |

Allocation, same rows:

| Shape | C++/CLI net462 | C++/CLI net10 | pure net48 | pure net48 ref | pure net10 | pure net10 ref |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| PowerShell | 281 B | 256 B | 281 B | **0 B** | 256 B | **0 B** |
| Network | 0 B | 0 B | 0 B | **0 B** | 0 B | **0 B** |

The Network row allocates nothing anywhere: an all-integer payload returns value types, so
there is nothing for either implementation to put on the heap. Its speedup — 7.8x from
C++/CLI net462 to the port's net10 ref path — is entirely decode cost.

The PowerShell row is where the ref path earns its existence. Both implementations allocate
identically through `IEventRecord`, because those bytes *are* the three `System.String`s the
contract returns and neither can avoid them. Only `EventRecordRef` removes them, which is
the difference between a busy trace producing garbage proportional to its event rate and
producing none.

### Filters

`Filter` builds an `EventFilter` with a payload predicate; `Inline` is the same predicate
evaluated directly in an `OnEventRef` handler.

| Shape | | C++/CLI net462 | C++/CLI net10 | pure net48 | pure net48 ref | pure net10 | pure net10 ref |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| PowerShell | match | 678.0 ns | 729.8 ns | 282.8 ns | 283.7 ns | 147.9 ns | **152.9 ns** |
| PowerShell | reject | 388.2 ns | 413.2 ns | 266.7 ns | 269.7 ns | 143.8 ns | **145.3 ns** |
| Network | match | 535.2 ns | 619.8 ns | 162.6 ns | 162.6 ns | 72.8 ns | **73.9 ns** |
| Network | reject | 280.3 ns | 308.7 ns | 155.9 ns | 155.5 ns | 71.7 ns | **71.1 ns** |

Inline, port only:

| Shape | | pure net48 | pure net10 |
| --- | --- | ---: | ---: |
| PowerShell | match | 281.0 ns | 140.7 ns |
| PowerShell | reject | 276.7 ns | 137.1 ns |
| Network | match | 155.0 ns | 64.1 ns |
| Network | reject | 153.7 ns | 64.5 ns |

Inline is 5–12% faster than `EventFilter` — the cost of the filter object is the virtual
predicate call and the id check, and it is small.

**This understates `EventFilter` in production.** `Proxy` drives the dispatch path directly
and therefore cannot exercise **event-id pushdown**: when a provider carries only filters,
`UserTrace` collects their event ids and asks ETW to drop everything else in the kernel
(`UserTrace.cs:707-711`), so a non-matching event never reaches managed code at all. That
optimisation is disabled for the whole provider GUID as soon as any provider-level handler
is attached (`UserTrace.cs:795`) — which is exactly what the inline arms do. So the `reject`
rows above measure the *worst* case for `EventFilter` and the *best* case for inline; with
pushdown active a rejected event costs nothing rather than ~70 ns. Prefer `EventFilter`.

### Reading it

The port gains far more from the modern runtime than the C++/CLI wrapper does. Dispatch goes
87.1 → 34.4 ns (2.5x) for the port, while C++/CLI gets *slower*, 273.7 → 341.1 ns. That is
expected in both directions: the C++/CLI hot path is native code the JIT never sees, so
runtime improvements bypass it, while the added managed/native transition cost on the newer
runtime is real. Every C++/CLI cell is flat or worse on .NET 10.

The one cell to be least confident about is OnMetadata on .NET Framework, where the port
loses outright. If a consumer's entire workload is metadata-only on .NET Framework, the port
is not an upgrade on speed — it is an upgrade on allocation, and only once they move to
`OnEventRef` or a newer runtime.

Both harnesses assert that the event handlers actually ran. This is not defensive
boilerplate: the first version of this benchmark reported the C++/CLI decode costing 1 ns
more than a no-op and allocating nothing, which looked like a spectacular result and was in
fact a measurement of nothing at all.

The cause was that `Proxy` does not keep the `UserTrace` it wraps alive. A trace held only
by a local was collected as soon as the constructor returned, after which `PushEvent`
silently delivered nothing. `ProxyBenchmarks` now roots its traces deliberately.

The lesson generalises: a benchmark that reports work as free is far more likely to be
broken than fast. Both harnesses now fail loudly instead.