# Parity suite

This project compiles the *same* test sources as `..\ManagedETWTests` — which were written
against the C++/CLI wrapper — but binds them to the pure .NET implementation in
`..\..\managed`. An API divergence between the two implementations surfaces here as a
compile error; a behavioural divergence surfaces as a test failure.

## Current state: green

84 tests, passing on both `net48` and `net10.0-windows`. The project is a member of
`managed\Krabs.Managed.slnx`.

```powershell
cd tests\ManagedETWTests.PureDotNet
dotnet test --nologo
```

Run it from *this* directory: `dotnet` resolves `global.json` from the current working
directory, not from the project path, and the pinned SDK lives here.

## Divergences the suite pinned down

Closing the gaps forced these behaviours to match the C++/CLI wrapper exactly:

| Behaviour | Resolution |
| --- | --- |
| `TypeMismatchAssert` | `[Conditional("DEBUG")]`, matching `krabs::debug::assert_valid_assignment` being compiled out under `NDEBUG`. Applied to the fixed-width numeric accessors only — not to strings, where the decoders branch on the in-type and legitimately accept the counted variants. |
| Fixed-width property size | Must match `sizeof(T)` *exactly*, like `krabs::parser::parse`. Accepting oversized properties was our own invention. |
| Missing property | Throws `ParserException`, the exact type the C++/CLI wrapper throws. The separate `PropertyNotFoundException` was removed. |
| `Predicate` operators | C++/CLI instance operators surface to C# as `op_LogicalAnd`/`op_LogicalOr`/`op_LogicalNot` instance methods, so those exist alongside the C# `&`/`|`/`!` operators. |
| MSTest version | Pinned to 2.2.10, same as `EtwTestsCS.csproj`. MSTest 3.x breaks `Assert.AreEqual<T>` inference in the shared sources. |
