# EU4 opinion snapshot CLI

`eu4-save-opinions` uses the vendored Jomini `eu4save` parser at commit
`8fbd6861f453c719da59daac6970babd9ddc19ac` (MIT). The CLI uses small custom
Serde models for the fields needed here; the upstream Jomini sources were not
modified.

Run it with an explicit save path:

```powershell
work/deps/jomini-rust-toolchain-120/eu4-save-opinions-r002.exe <save-path>
```

The JSON payload schema is `eu4.save_opinion_snapshot.v1`. It includes metadata,
the sorted list of non-sentinel saved country tags, and one row for each such
country. Each country's `active_relations` is `null` when that field is absent
or null, and an empty list when the saved map has no opinion-bearing rows.
`relation_projection` is `serialized_opinion_entries_only`: every raw relation
row is checked, but rows without an `opinion` entry are omitted to keep the
snapshot bounded. Top-level counters report `raw_relation_rows_scanned`,
`retained_relation_rows`, and `opinion_rows`. Each emitted relation keeps its
saved target tag and ordered opinion rows.
Opinion rows preserve `modifier`, the recorded `date` string,
`current_opinion` as decimal text, and `expiry_date` as a nullable boolean.
The date is only the date stored on the row; it does not establish when the
modifier took effect or expires. `cached_sum`, trust, attitude, and other fields
are not exported.

This is an operator-internal parser output for all non-sentinel countries. A
consumer must apply its bound observer and target scope before publication; the
complete snapshot must not be exposed directly as a player's view. The parser
does not calculate final opinion, decay, application time, or expiry time.

The default input and expanded-data limit is 128 MiB, stdout is limited to
16 MiB, and the parser rejects more than 4,096 countries, 4,096 raw relation
rows in one country, 16,777,216 raw relation rows overall, 65,536 retained
relation rows, or 65,536 opinion rows. It supports `Text` and `TextZip`;
`Binary` is rejected.
This implementation's fixture tests cover the parser contract. They do not
claim validation of every save encoding or game version.

Build from the repository root with the isolated Rust toolchain configured in
`work/deps/jomini-rust-toolchain-104`:

```powershell
cargo build --offline --release --jobs 1 --manifest-path tools/rust/eu4-save-opinions/Cargo.toml
```

For the monitored build and generated trust manifest, see
`work/runtime/information-opinion-reuse-20261103-120-001/cli-001/run_cli_monitored.py`
and `generate_manifest.py`. The current executable is
`work/deps/jomini-rust-toolchain-120/eu4-save-opinions-r002.exe`; its pinned
manifest is `tools/rust/eu4-save-opinions/adapter-manifest.json`. Revision 1 is
archived under `work/runtime/information-opinion-reuse-20261103-120-001/cli-001/revision-001/`.
After any rebuild, regenerate and review the manifest's binary and source hashes
before trusting the new executable. The earlier province and empire CLI
binaries and manifests are separate and unchanged.
