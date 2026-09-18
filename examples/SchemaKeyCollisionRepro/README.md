# Repro: TraceLogging events that share a name collide in the schema cache

Minimal, self-contained repro for [#193](https://github.com/microsoft/krabsetw/issues/193).

TraceLogging events are identified by name rather than event id (the id is `0`). A provider may
emit the same event name from several call sites with **different fields** — this is legal, and
real providers do it. `Microsoft.Windows.AppLifeCycle.UI`, for example, emits
`AppLaunch_UserClick` both with and without a leading `PartA_PrivTags` field.

Those variants share every field of `schema_key` — provider, name, id, version, opcode, level
and keyword — so they collide in `schema_locator`'s cache. The first schema decoded is reused
for every variant, and the decoded values come out shifted by the size of the missing field.

## What this program does

It registers its own TraceLogging provider, emits two variants of a single event name, consumes
them with krabs, and prints the field names krabs decoded for each. No external provider, ETL
file, or third-party tool is needed.

| Variant | Fields emitted |
| --- | --- |
| A | `entryPoint` (UInt32), `appId` (string) |
| B | `PartA_PrivTags` (UInt64), `entryPoint` (UInt32), `appId` (string) |

Variant A is emitted first so that its smaller schema is the one cached.

## Build and run

From a Developer Command Prompt. `UNICODE` is required by krabs itself — without it
`KERNEL_LOGGER_NAME` resolves to the ANSI variant and `kt.hpp` fails to compile.

```
cl /std:c++17 /EHsc /DUNICODE /D_UNICODE /I..\..\krabs ^
   schema_key_collision_repro.cpp advapi32.lib tdh.lib

schema_key_collision_repro.exe
```

Starting a real-time ETW session requires membership in **Administrators** or
**Performance Log Users**. If you are in neither, run the program from an elevated prompt.

## Expected output

Before the fix (exit code `1`):

```
variant A -> entryPoint, appId
variant B -> entryPoint, appId

RESULT: FAIL - both variants decoded with the same schema (2 fields).
```

Variant B is decoded with variant A's schema: `PartA_PrivTags` is missing entirely, and
`entryPoint` reports `50331648` — the first four bytes of the `PartA_PrivTags` value.

After the fix (exit code `0`):

```
variant A -> entryPoint, appId
variant B -> PartA_PrivTags, entryPoint, appId

RESULT: PASS - each variant decoded with its own schema.
```

The program exits `0` on PASS, `1` on FAIL, and `2` if it could not run (for example, fewer
than two events were received because the session could not be started), so it can be used
directly as a regression check.
