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

Four cells: {.NET Framework, .NET 10} x {C++/CLI, pure .NET}. All Release, x64, same
machine, all run in-process (`-i`) so every cell is measured identically. Times are per
event. All four cells were collected in a single sitting.

### .NET Framework (C++/CLI net462 vs pure net48)

| | C++/CLI | Pure .NET | |
| --- | ---: | ---: | ---: |
| Dispatch | 294.7 ns | 90.1 ns | 3.3x |
| Decode 3 strings | 1402.0 ns | 506.4 ns | 2.8x |
| Filter, match | 660.8 ns | 295.9 ns | 2.2x |
| Filter, reject | 386.3 ns | 277.0 ns | 1.4x |

### .NET 10 (C++/CLI net8.0 rolled forward vs pure net10.0)

| | C++/CLI | Pure .NET | |
| --- | ---: | ---: | ---: |
| Dispatch | 235.4 ns | 25.6 ns | 9.2x |
| Decode 3 strings | 1207.8 ns | 263.6 ns | 4.6x |
| Filter, match | 570.2 ns | 136.0 ns | 4.2x |
| Filter, reject | 343.8 ns | 131.3 ns | 2.6x |

### Allocation

Identical in every cell: 0 B except `DecodeThreeStrings`, which is 281 B on .NET Framework
and 256 B on .NET 10 for both implementations. Those are the three `System.String`s the
`IEventRecord` API contractually returns, so neither implementation can avoid them. The
C++/CLI double copy (payload to `std::wstring` to `String^`) costs time, not surviving
bytes.

### The ref API

Zero-allocation decoding needs `OnEventRef`/`EventRecordRef`, which the C++/CLI wrapper has
no equivalent of and which the matrix above therefore cannot compare. Measured separately in
`managed\benchmarks` over 256 captured records, per event:

| | Span (`EventRecordRef`) | Compat (`IEventRecord`) |
| --- | ---: | ---: |
| net48 | 247 ns, 0 B | 338 ns, 64 B |
| net10.0 | 121 ns, 0 B | 147 ns, 56 B |

The interesting number is the allocation, not the time: the span path is the only one of the
three APIs measured anywhere in this directory that survives a busy trace without producing
garbage.

### Reading it

The pure port gains far more from the modern runtime than the C++/CLI wrapper does:
dispatch goes 90.1 to 25.6 ns (3.5x) for the port, but only 294.7 to 235.4 ns (1.25x) for
C++/CLI. That is expected -- the C++/CLI hot path is native code the .NET JIT never sees, so
runtime improvements largely bypass it. End to end, pure .NET on .NET 10 dispatches 11.5x
faster than C++/CLI on .NET Framework.

`Filter, reject` is the weakest cell (1.4x on .NET Framework) and the one to be least
confident about.

Both harnesses assert that the event handlers actually ran. This is not defensive
boilerplate: the first version of this benchmark reported the C++/CLI decode costing 1 ns
more than a no-op and allocating nothing, which looked like a spectacular result and was in
fact a measurement of nothing at all.

The cause was that `Proxy` does not keep the `UserTrace` it wraps alive. A trace held only
by a local was collected as soon as the constructor returned, after which `PushEvent`
silently delivered nothing. `ProxyBenchmarks` now roots its traces deliberately.

The lesson generalises: a benchmark that reports work as free is far more likely to be
broken than fast. Both harnesses now fail loudly instead.