# CWTools read-only EU4 script AST CLI

This small CLI calls the official `CWTools.Parser.CKParser.parseString` parser.
It parses syntax only; it does not evaluate conditions, resolve scopes, or run
effects.

The command accepts 1–16 explicit file paths per process and caps their total
input size at 4 MiB. Each file receives its own result in one JSON response with
schema `eu4.cwtools.script_ast.v1`. Input bytes are hashed before decoding.
UTF-8 BOM is honored; otherwise strict UTF-8 is preferred and strict Windows
1252 is used when the bytes are not valid UTF-8. No replacement fallback is
used.

Each ordered `items` entry keeps repeated keys and bare values. Key/value
entries include `key` and `operator`; blocks use `value_kind: "block"` and an
ordered `children` array. Scalar `value_kind` distinguishes strings, quoted
strings, integers, decimals, and booleans. Comments are retained as comment
nodes. The source line is 1-based; source columns are the 0-based values
provided by CWTools ranges. `end_line` and `end_column` are copied from the same
range. A syntax failure is reported per file with `parse_ok: false` and the
parser's error text; the CLI does not fall back to another parser.

Package pins: CWTools 0.6.0-alpha and FSharp.Core 9.0.303, targeting .NET 8.
FSharp.Core 9 is required because the CWTools assembly references assembly
version 9.0.0.0; the .NET 8 SDK otherwise selects FSharp.Core 8 by default.
The NuGet metadata does not embed a CWTools license expression; the upstream
repository ships the MIT license, copied to `CWTOOLS-LICENSE-MIT.txt`.
NuGet currently resolves CSharpHelpers and Shared to 1.0.0, whose package
assets target .NET Framework; restore reports NU1701 for both. The runtime
smoke successfully parsed valid and malformed script inputs with this graph.
All exact package resolutions and license metadata are in `packages.lock.json`
and `adapter-manifest.json`; missing or placeholder transitive license
metadata is recorded as such rather than inferred.

Build output is in `bin/Release/net8.0`. Runtime invocation is recorded in
`adapter-manifest.json`; it uses the workspace-isolated .NET host under
`work/deps`, followed by `CwtoolsScript.dll` and the explicit input paths.
