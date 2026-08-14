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
sitting. Times are per event, on one synthetic record with three string properties.

`ref` is the `OnEventRef`/`EventRecordRef` path reading the same three strings as spans. The
C++/CLI wrapper has no equivalent API, so those cells are the port's alone; `Dispatch` and
the filters have no ref variant because neither materialises a string in the first place.

| | C++/CLI net462 | net48 `IEventRecord` | net48 ref | C++/CLI net8.0 | net10 `IEventRecord` | net10 ref |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Dispatch | 282.8 ns | 89.0 ns | -- | 231.1 ns | 30.3 ns | -- |
| Decode 3 strings | 1410.8 ns | 500.8 ns | **409.7 ns** | 1181.3 ns | 247.3 ns | **182.0 ns** |
| Filter, match | 651.7 ns | 300.9 ns | -- | 582.0 ns | 135.2 ns | -- |
| Filter, reject | 379.2 ns | 282.9 ns | -- | 347.3 ns | 130.5 ns | -- |
| Allocated, decode | 281 B | 281 B | **0 B** | 256 B | 256 B | **0 B** |

The C++/CLI net8.0 column is the net8.0 build rolled forward onto the .NET 10 runtime: the
C++/CLI toolset has no net10.0 target, and running the net8.0 assembly under `RollForward=Major`
is what a consumer upgrading their host would actually get.

### Reading it

Every cell outside the decode row allocates nothing in either implementation. In the decode
row both implementations allocate the same amount -- 281 B on .NET Framework, 256 B on
.NET 10 -- because those are the three `System.String`s the `IEventRecord` contract returns
and neither implementation can avoid them. The C++/CLI double copy (payload to `std::wstring`
to `String^`) costs time, not surviving bytes. Only the ref column removes the allocation,
and that is the point of it: it is the difference between a busy trace producing garbage
proportional to its event rate and producing none.

The port gains far more from the modern runtime than the C++/CLI wrapper does: dispatch goes
89.0 to 30.3 ns (2.9x) for the port and only 282.8 to 231.1 ns (1.2x) for C++/CLI. That is
expected -- the C++/CLI hot path is native code the JIT never sees, so runtime improvements
largely bypass it. End to end, the ref path on .NET 10 decodes three strings 7.8x faster than
C++/CLI on .NET Framework, and without allocating.

`Filter, reject` is the weakest cell (1.3x on .NET Framework) and the one to be least
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