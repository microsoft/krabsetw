
Overview
========
krabsetw is a C++ library that simplifies interacting with ETW. It allows for any number of traces and providers to be enabled and for client code to register for event notifications from these traces.

krabsetw also provides code to simplify parsing generic event data into strongly typed data types.

This repository provides **three options** for consuming and decoding Windows ETW events:

| Option | Package | Implementation |
| --- | --- | --- |
| **Native C++** | `Microsoft.O365.Security.Krabsetw` | The header-only **krabsetw** library for native C++ applications. |
| **.NET C++/CLI (4.x)** | `Microsoft.O365.Security.Native.ETW` | A C++/CLI wrapper over **krabsetw**, deployed as a mixed-mode .NET assembly for x64 or ARM64. Also known as **Lobsters**. |
| **Pure .NET (package 5.x)** | `Microsoft.O365.Security.ETW` | A standalone .NET implementation that calls ETW and TDH directly, with AnyCPU deployment and no C++/CLI or mixed-mode assembly dependency. |

The **pure .NET implementation (package 5.x)** lives in `managed`. It targets .NET Framework 4.6.2 and 4.8, .NET 8, and .NET 10 on Windows. Its allocation-free reading surface (`EventRecordRef`, a `ref struct`) lets callers inspect and filter payloads without materialising strings or arrays.

The [included proxy-based benchmarks](benchmarks/README.md) show roughly 1.4x–10x faster callback processing than the C++/CLI wrapper, depending on the workload and runtime. These are callback-processing microbenchmarks, not end-to-end ETW throughput measurements.

**5.0 is a separate package, not an in-place update to the C++/CLI package.** The namespace remains `Microsoft.O365.Security.ETW`, but source compatibility is partial and there is **no binary compatibility**. **Rebuild all consumers** and review behavior and breaking changes before migrating.

* [Migration guide](managed/MIGRATION.md) — breaking-change checklists, migration steps, allocation-free access, and testing helpers.
* [Parity guide](managed/PARITY.md) — implementation differences and the status of native correctness backports.

Examples & Documentation
========

* An [ETW Primer](docs/EtwPrimer.md).
* Simple examples can be found in the `examples` folder.
* Native C++ examples: [KrabsExample.md](docs/KrabsExample.md).
* .NET C++/CLI (4.x) examples: [LobstersExample.md](docs/LobstersExample.md).
* Pure .NET (package 5.x) examples and migration: [managed/MIGRATION.md](managed/MIGRATION.md).
* SampleKrabsCSharpExe is a non-trivial example demonstrating how to manage the trace objects.
* [Using Message Analyzer to find new ETW event sources.](docs/UsingMessageAnalyzerToFindETWSources.md)

Important Notes
==============
* `krabsetw` and `Microsoft.O365.Security.Native.ETW` only support x64 and ARM64. No effort has been made to support x86.
* `krabsetw` and `Microsoft.O365.Security.Native.ETW` are only supported on Windows 7 or Windows 2008R2 machines and above.
* Throwing exceptions in the event handler callback or krabsetw or Microsoft.O365.Security.Native.ETW will cause the trace to stop processing events.
* The call to "start" on the trace object is blocking so thread management may be necessary.
* The native C++ and .NET C++/CLI Visual Studio solution is `krabs\krabs.sln`. For pure .NET (package 5.x), run `dotnet build Krabs.Managed.slnx` from the `managed` directory so its `global.json` selects the .NET 10 SDK.
* When building a native code binary using the `krabsetw` package, please refer to the [compilation readme](krabs/README.md) for notes about the `TYPEASSERT` and `NDEBUG` compilation flags.

NuGet Packages
==============
| Option | Package availability |
| --- | --- |
| Native C++ | [Microsoft.O365.Security.Krabsetw](https://www.nuget.org/packages/Microsoft.O365.Security.Krabsetw/) |
| .NET C++/CLI (4.x) | [Microsoft.O365.Security.Native.ETW](https://www.nuget.org/packages/Microsoft.O365.Security.Native.ETW/) |
| Pure .NET (package 5.x) | [Microsoft.O365.Security.ETW](https://www.nuget.org/packages/Microsoft.O365.Security.ETW/) |

The legacy wrapper also has a [Microsoft.O365.Security.Native.ETW.Debug](https://www.nuget.org/packages/Microsoft.O365.Security.Native.ETW.Debug/) package for development, providing type asserts.

To pack version 5.x, run `dotnet pack Krabs.Managed.slnx` from the `managed` directory.

For verifying the legacy C++/CLI binary's strong name, you can use the following command:
`sn -T Microsoft.O365.Security.Native.ETW.dll`

The expected output is:
```
Microsoft (R) .NET Framework Strong Name Utility  Version 4.0.30319.0
Copyright (c) Microsoft Corporation.  All rights reserved.

Public key token is 31bf3856ad364e35
```

Community & Contact
==============
Please feel free to file issues through GitHub for bugs and feature requests and we'll respond to them as quickly as we're able.
