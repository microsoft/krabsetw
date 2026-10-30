# Microsoft.O365.Security.ETW

A pure .NET library for consuming and decoding Windows Event Tracing for Windows
(ETW) events. It calls ETW and TDH directly, without a C++/CLI or mixed-mode assembly
dependency.

## Installation

```shell
dotnet add package Microsoft.O365.Security.ETW --version 5.0.0
```

The package targets .NET Framework 4.6.2 and 4.8, .NET 8, and .NET 10 on Windows.
It ships AnyCPU assemblies for x64 and ARM64 consumers. Live ETW sessions may
require elevated permissions, depending on the session and provider.

## Reading and testing events

- Use `IEventRecord` for compatibility-oriented event access.
- Use the `EventRecordRef` ref-struct API for allocation-free payload reads and
  filtering. Materializing strings, arrays and other objects may allocate.
- Use the synthetic record/schema builders and proxy helpers to test handlers
  without a live ETW session.

Event records are callback-scoped: do not retain them after the callback returns.
Copy any values that need to outlive the callback.

## Migrating from the C++/CLI wrapper

Version 5.0 is a **separate package**, not an in-place update to
`Microsoft.O365.Security.Native.ETW` 4.x. The namespace remains
`Microsoft.O365.Security.ETW`, but source compatibility is partial and there is
**no binary compatibility**. Rebuild all consumers and review the
[breaking changes and migration examples](https://github.com/microsoft/krabsetw/blob/master/managed/MIGRATION.md).

## Documentation and debugging

- [Migration guide and examples](https://github.com/microsoft/krabsetw/blob/master/managed/MIGRATION.md)
- [Implementation parity and differences](https://github.com/microsoft/krabsetw/blob/master/managed/PARITY.md)
- [Proxy-based callback-processing benchmarks](https://github.com/microsoft/krabsetw/blob/master/benchmarks/README.md)
- [Source repository](https://github.com/microsoft/krabsetw)

A companion `.snupkg` contains portable debugging symbols. Source Link maps the
symbols to the exact GitHub source commit used to build the package.

Licensed under the [MIT license](https://github.com/microsoft/krabsetw/blob/master/LICENSE).
