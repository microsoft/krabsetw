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
| PowerShell | 57.5 ns | 37.8 ns | 40.6 ns | **14.9 ns** |
| Network | 57.4 ns | 38.4 ns | 40.4 ns | **14.8 ns** |

1.4x faster on .NET Framework, 2.5x on .NET 10.

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
| PowerShell | 275.8 ns | 247.9 ns | 67.4 ns | 68.0 ns | 33.7 ns | **32.4 ns** |
| Network | 290.8 ns | 256.9 ns | 68.0 ns | 67.9 ns | 33.7 ns | **34.0 ns** |

4.1x faster on .NET Framework, 7.4x on .NET 10. `ref` and compat are the same here because
neither materialises a value.

### Decode — every property read

| Shape | C++/CLI net462 | C++/CLI net10 | pure net48 | pure net48 ref | pure net10 | pure net10 ref |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| PowerShell (3 strings) | 1491.5 ns | 1251.7 ns | 469.6 ns | 374.6 ns | 272.5 ns | **189.4 ns** |
| Network (8 integers) | 941.3 ns | 808.2 ns | 243.4 ns | 195.6 ns | 148.2 ns | **112.9 ns** |

Allocation, same rows:

| Shape | C++/CLI net462 | C++/CLI net10 | pure net48 | pure net48 ref | pure net10 | pure net10 ref |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| PowerShell | 281 B | 256 B | 281 B | **0 B** | 256 B | **0 B** |
| Network | 0 B | 0 B | 0 B | **0 B** | 0 B | **0 B** |

The Network row allocates nothing anywhere: an all-integer payload returns value types, so
there is nothing for either implementation to put on the heap. Its speedup — 8.3x from
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
| PowerShell | match | 676.3 ns | 601.2 ns | 266.9 ns | 268.2 ns | 146.7 ns | **149.0 ns** |
| PowerShell | reject | 380.2 ns | 343.2 ns | 258.7 ns | 258.0 ns | 142.8 ns | **143.2 ns** |
| Network | match | 536.6 ns | 480.6 ns | 110.6 ns | 110.1 ns | 59.9 ns | **61.2 ns** |
| Network | reject | 278.6 ns | 245.7 ns | 107.6 ns | 107.6 ns | 58.7 ns | **58.5 ns** |

Inline, port only:

| Shape | | pure net48 | pure net10 |
| --- | --- | ---: | ---: |
| PowerShell | match | 246.9 ns | 140.4 ns |
| PowerShell | reject | 236.2 ns | 136.1 ns |
| Network | match | 103.1 ns | 51.4 ns |
| Network | reject | 103.6 ns | 51.4 ns |

Inline is 6–16% faster than `EventFilter` — the cost of the filter object is the virtual
predicate call and the id check, and it is small.

**This understates `EventFilter` in production.** `Proxy` drives the dispatch path directly
and therefore cannot exercise **event-id pushdown**: when a provider carries only filters,
`UserTrace` collects their event ids and asks ETW to drop everything else in the kernel
(`UserTrace.cs:707-711`), so a non-matching event never reaches managed code at all. That
optimisation is disabled for the whole provider GUID as soon as any provider-level handler
is attached (`UserTrace.cs:795`) — which is exactly what the inline arms do. So the `reject`
rows above measure the *worst* case for `EventFilter` and the *best* case for inline; with
pushdown active a rejected event costs nothing rather than 60–110 ns. Prefer `EventFilter`.

### Reading it

The port wins every cell on both runtimes, by 1.4x at the narrowest (metadata on .NET
Framework) and 8.3x at the widest (Network decode, C++/CLI net462 against the port's net10
ref path).

The port also gains more from the modern runtime than the C++/CLI wrapper does. Dispatch
goes 67.4 → 33.7 ns (2.0x) for the port against 275.8 → 247.9 ns (1.1x) for C++/CLI. That
asymmetry is expected: the C++/CLI hot path is native code the JIT never sees, so runtime
improvements largely bypass it, while the port is managed end to end and collects them in
full.

An earlier revision of this file claimed C++/CLI got *slower* on .NET 10 — dispatch 273.7 →
341.1 ns. Re-measuring the whole matrix in one sitting did not reproduce it: every C++/CLI
cell is faster on .NET 10, by 10–20%. The claim was an artefact of comparing arms collected
at different times, which is why the matrix is now regenerated as a set.

The narrowest margin is metadata on .NET Framework (40.4 vs 57.4 ns). It is also the row
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