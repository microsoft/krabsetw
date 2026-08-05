# Parity suite

This project compiles the *same* test sources as `..\ManagedETWTests` — which were written
against the C++/CLI wrapper — but binds them to the pure .NET implementation in
`..\..\managed`. An API divergence between the two implementations surfaces here as a
compile error; a behavioural divergence surfaces as a test failure.

## Current state: does not compile yet

The port is a vertical slice. Compiling this project is what tells us what is still missing,
and right now it reports three gaps:

| Missing | Used by | Notes |
| --- | --- | --- |
| `Microsoft.O365.Security.ETW.Testing` — `Proxy`, `SynthRecord`, `RecordBuilder` | every `describe_*` test | The differential oracle. Lets tests synthesise a record against a real registered schema and push it through a filter without an ETW session. Highest value of the three: it makes the sizing and offset-walking tests deterministic. |
| `Microsoft.O365.Security.ETW.Kernel` — `KernelTrace` and the kernel provider types | `describe_EventRecord`, `describe_OnError`, `describe_Proxy` | Kernel (NT Kernel Logger / system) traces. A separate feature from user traces, not part of the slice. |
| `TypeMismatchAssert`, `ParserException` | `describe_Asserts`, `describe_InvalidParsing` | The debug-build type-mismatch assertion machinery from `krabs::debug`. |

To regenerate the list:

```powershell
cd tests\ManagedETWTests.PureDotNet
dotnet build --nologo 2>&1 | Select-String "error CS" | Sort-Object -Unique
```

The project is deliberately not a member of any solution, so it does not break `krabs.sln`
or `Krabs.Managed.slnx` while the gaps are open. Add it to `Krabs.Managed.slnx` once it
compiles.
