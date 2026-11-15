# EU4 1.37.4 battle body format input candidate

This candidate builds bounded, value-only `NativeArg104` entries from caller-owned
strings. It does not invoke a formatter, allocate engine memory, attach to a process,
or read a game pointer. Its ABI contract is the static receipt
`work/runtime/information-diplomacy-state-20261028-001/battle-body-query-source-001/format-input-contract-001.json`
(SHA-256 `e9e63128db261db57fbca890f0830371829825f451df602449da114649d65817`).

The builder copies the base definition key with a literal `_1` suffix and every row
key/value into a 32 KiB workspace arena. It keeps the returned 104-byte views in one
noncopyable, nonmovable workspace. Limits are 64 rows, 256 bytes per complete key,
8192 bytes per value, and 32 KiB total arena storage. It rejects embedded NUL,
duplicate row keys, aliased input ranges, count overflow, and arena overflow. The
existing `build()` overload is unchanged: if given its optional resolved template,
it still uses the conservative legacy estimate
`template_bytes + count('$') * (8192 + 8)` and rejects a bound at or above 60 KiB.

The new `build_for_bound_template(base, rows, resolved_template)` entry point uses
the fixed-array type-2 expansion planner. It scans paired `$` tokens, binds each key
to one supplied type-2 row, accounts for the value bytes plus up to four color bytes,
and includes the terminating NUL in its bound. Missing keys, an invalid or oversized
template, embedded NUL, duplicate rows, aliases, or a bound at or above 60 KiB clear
the workspace and fail. On success it delegates the actual 104-byte construction
to the existing no-template `build()` path, preserving the literal `_1` key,
argument order, and workspace-owned stable pointers. This is still a value-only
builder; it does not invoke a formatter or native function.

The fixture compares the builder's 104-byte result with one execution of the exact
59-byte leaf pinned at RVA `0x6fbfa0`. It copies those fixed bytes to one `VirtualAlloc`
page owned by the fixture process, changes that page from RW to RX, invokes the leaf
using the same owned key/value pointers, and verifies the return value and bytes.
The only executable bytes are compiled into `owned_leaf_fixture.cpp`; no user-supplied
code or target address is accepted. The page is released with `VirtualFree` and its
freed state checked.

The runner is inert by default:

```powershell
C:/Users/wangyufei/anaconda3/envs/research/python.exe -B work/candidates/information-battle-format-input-1374/run_fixture.py
```

Only the explicit test-only flag compiles and executes the owned fixture. Attempts 1
and 2 are preserved in the stage with their source snapshots, failed receipts, and
binaries. Attempt 1 had an incorrect `$` count in its test expectation; attempt 2
exposed a builder defect where repeated successful builds appended into stale arena
state. Both stopped before the fixed leaf call. The current builder resets only after
alias, input, and required-capacity checks pass, and a regression exercises two
successive builds on one workspace. A corrected candidate uses a new attempt number
and refuses to overwrite any prior result receipt or executable:

```powershell
C:/Users/wangyufei/anaconda3/envs/research/python.exe -B work/candidates/information-battle-format-input-1374/run_fixture.py --test-only --attempt 3
```

The runner verifies the contract SHA, its five pinned REA evidence files, and the
current installation manifest's recorded game SHA before compiling. It records all
candidate source pins and the fixture result under
`work/runtime/information-diplomacy-state-20261028-001/battle-body-query-source-001/owned-input-fixture-001/`.
The installation manifest does not contain an executable path, so this runner does
not rediscover or open the game binary. The manifest records the expected EXE SHA
`b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77`.

The separate `format_expansion_plan_runner.py --test-only` compiles the planner and
bound-template builder tests only. It does not call the pinned 59-byte leaf, the
formatter, or the game. A test template with repeated small values only validates
the size-plan and 104-byte input-construction path; it is not a native-call
qualification.

The read-only `current-templates-001.json` receipt records that the two body keys
`LANDBATTLEOVER_1` and `NAVALBATTLEOVER_1` are each only the six-byte literal
`$NAME$`; button strings are readable separately. This supplies a name token, not a
complete battle body or its other controls. No current-event binding, full B04
text, layout, or visibility is established here. The earlier owned-leaf attempt 3
remains preserved and successful; these planner/builder tests do not rerun it.
