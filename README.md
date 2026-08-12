
Overview
========

**krabsetw** is a C++ library that simplifies interacting with ETW. It allows for any number of traces and providers to be enabled and for client code to register for event notifications from these traces.

**krabsetw** also provides code to simplify parsing generic event data into strongly typed data types.

**Microsoft.O365.Security.Native.ETW** is a C++ CLI (.NET) wrapper around **krabsetw**. It provides the same functionality as **krabsetw** to .NET applications and is used in production by the Office 365 Security team. It's affectionately referred to as **Lobsters**.

**Microsoft.O365.Security.ETW** is a pure .NET reimplementation of that wrapper, in `managed`. It talks to ETW and TDH directly rather than through **krabsetw**, so it needs no C++ toolchain to build and no mixed-mode assembly to deploy. It keeps the C++/CLI public surface, and adds an allocation-free reading surface (`EventRecordRef`, a `ref struct`) for callers that want to filter events without putting anything on the GC heap. It targets .NET Framework 4.6.2 and 4.8 as well as modern .NET.

* [managed/MIGRATION.md](managed/MIGRATION.md) — what changes when moving from the C++/CLI assembly, and how to use the allocation-free surface.
* [managed/PARITY.md](managed/PARITY.md) — where the two implementations deliberately differ, and defects open on either side.

Examples & Documentation
========

* An [ETW Primer](docs/EtwPrimer.md).
* Simple examples can be found in the `examples` folder.
* Please refer to [KrabsExample.md](docs/KrabsExample.md) and [LobstersExample.md](docs/LobstersExample.md) for detailed examples.
* SampleKrabsCSharpExe is a non-trivial example demonstrating how to manage the trace objects.
* [Using Message Analyzer to find new ETW event sources.](docs/UsingMessageAnalyzerToFindETWSources.md)

Important Notes
==============
* `krabsetw` and `Microsoft.O365.Security.Native.ETW` only support x64 and ARM64. No effort has been made to support x86.
* `krabsetw` and `Microsoft.O365.Security.Native.ETW` are only supported on Windows 7 or Windows 2008R2 machines and above.
* Throwing exceptions in the event handler callback or krabsetw or Microsoft.O365.Security.Native.ETW will cause the trace to stop processing events.
* The call to "start" on the trace object is blocking so thread management may be necessary.
* The Visual Studio solution is krabs\krabs.sln. The pure .NET library builds on its own with `dotnet build managed\Krabs.Managed.slnx`.
* When building a native code binary using the `krabsetw` package, please refer to the [compilation readme](krabs/README.md) for notes about the `TYPEASSERT` and `NDEBUG` compilation flags.

NuGet Packages
==============
NuGet packages are available both for the krabsetw C++ headers and the Microsoft.O365.Security.Native.ETW .NET library:
* https://www.nuget.org/packages/Microsoft.O365.Security.Native.ETW/
* https://www.nuget.org/packages/Microsoft.O365.Security.Native.ETW.Debug/ (for development - provides type asserts)
* https://www.nuget.org/packages/Microsoft.O365.Security.Krabsetw/

The pure .NET library packs as `Microsoft.O365.Security.ETW` (`dotnet pack managed\Krabs.Managed.slnx`). It is not published yet.

For verifying the .NET binaries, you can use the following command:
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
