# Head-to-head benchmarks

`Shared\ProxyBenchmarks.cs` is compiled twice — once against the C++/CLI wrapper
(`Krabs.Benchmarks.Cli`, net462) and once against the pure .NET port
(`Krabs.Benchmarks.Pure`, net48). Same source, same machine, same CLR family, both
Release. That is what makes the comparison meaningful.

Events are driven through `Testing.Proxy` rather than a live ETW session. A real session
would mostly measure the kernel's buffering and flush cadence, which is identical for both
implementations and would swamp the difference being measured. What is measured is
everything from the trace's event callback inwards: provider matching, schema resolution,
predicate evaluation and property decoding.

## Running

The C++/CLI wrapper must be built first — its vcxproj needs MSBuild.exe from Visual Studio
and cannot be imported by the dotnet CLI, so it is referenced as a built assembly:

```powershell
msbuild krabs\krabs.sln /t:Microsoft_O365_Security_Native_ETW `
        /p:Configuration=Release /p:Platform=x64

cd benchmarks\Krabs.Benchmarks.Cli
dotnet build -c Release
.\bin\Release\net462\Krabs.Benchmarks.Cli.exe

cd ..\Krabs.Benchmarks.Pure
dotnet build -c Release
.\bin\Release\net48\Krabs.Benchmarks.Pure.exe
```

Pass `--manual` to either executable for a plain stopwatch harness. It exists as a
cross-check on BenchmarkDotNet, and it reports a `sink/event` column.

## The sink/event column matters

Both harnesses assert that the event handlers actually ran. This is not defensive
boilerplate: the first version of this benchmark reported the C++/CLI decode costing 1 ns
more than a no-op and allocating nothing, which looked like a spectacular result and was in
fact a measurement of nothing at all.

The cause was that `Proxy` does not keep the `UserTrace` it wraps alive. A trace held only
by a local was collected as soon as the constructor returned, after which `PushEvent`
silently delivered nothing. `ProxyBenchmarks` now roots its traces deliberately.

The lesson generalises: a benchmark that reports work as free is far more likely to be
broken than fast. Both harnesses now fail loudly instead.
