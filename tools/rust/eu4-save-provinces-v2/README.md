# EU4 省份关系快照 CLI v2

这个版本在 v1 的省份快照上增加 `territorial_core`，用于保留存档中单独记录的领土核心标记。CLI 输出 `eu4.save_provinces_snapshot.v2`；受信 manifest 仍使用解析器身份格式 `eu4.save_provinces.parser.v1`。

`territorial_core` 是非空国家标签列表，表示存档明确写出的领土核心标记；没有这个标记时输出 `null`。它不表示完整核心，也不区分永久宣称或宣称期限。现有 `cores`、`claims`、`discovered_by` 及省份 ID 处理沿用 v1。共同的解析方式、国家哨兵、输入边界和 token resolver 限制见 [v1 README](../eu4-save-provinces/README.md)。

本版复用固定 Jomini commit `8fbd6861f453c719da59daac6970babd9ddc19ac`（MIT），用独立的小型 serde 模型读取顶层字段；没有改动上游模型，也没有改动 v1 的 Cargo 源码、manifest、二进制或 77 个来源 pin。

## 构建与本批产物

从仓库根目录构建：

```powershell
cargo build --release --jobs 1 --manifest-path tools/rust/eu4-save-provinces-v2/Cargo.toml
```

本批复用 work/deps 下的隔离工具链和 Cargo target 缓存；命令行构建时可这样指定隔离目录：

```powershell
$repo = (Resolve-Path '.').Path
$env:CARGO_HOME = Join-Path $repo 'work/deps/jomini-rust-toolchain-104/cargo-home'
$env:RUSTUP_HOME = Join-Path $repo 'work/deps/jomini-rust-toolchain-104/rustup-home'
$env:CARGO_TARGET_DIR = Join-Path $repo 'work/deps/jomini-rust-toolchain-104/build-target-revision2'
$env:PATH = (Join-Path $env:CARGO_HOME 'bin') + ';' + $env:PATH
cargo build --release --jobs 1 --manifest-path tools/rust/eu4-save-provinces-v2/Cargo.toml
```

0.5 秒进程树监控构建脚本是 [build_monitored_001.py](../../../work/runtime/information-save-interests-20261102-001/territorial-core-v2-001/build_monitored_001.py)，构建收据为 [cargo-build-receipt-001.json](../../../work/runtime/information-save-interests-20261102-001/territorial-core-v2-001/cargo-build-receipt-001.json)。manifest 生成脚本是 [create_adapter_manifest_001.py](../../../work/runtime/information-save-interests-20261102-001/territorial-core-v2-001/create_adapter_manifest_001.py)。重新编译或修改受信源码后，必须更新 manifest 中的 binary 与 source hashes，不能沿用旧值。

- 可执行文件：[eu4-save-provinces-v2.exe](../../../work/deps/jomini-rust-toolchain-105/eu4-save-provinces-v2.exe)；SHA-256 `f618674149c58a0382fab3b3e8654a687fd0b17ca3f3bb4d457defdd0ec1d658`。
- 受信 manifest：[adapter-manifest.json](adapter-manifest.json)；SHA-256 `a5d6a1b3779ca3de1944aa44cf91be4925f5df325165569c9862a08d1e7b790e`，固定 77 个源码 pin。
- 本批一次只读存档解析及与 v1 的逐省比较：[v2-inspection-001.json](../../../work/runtime/information-save-interests-20261102-001/territorial-core-v2-001/v2-inspection-001.json)。该解析验证 EU4 1.37.4 的 Text 存档；代码保留 TextZip 分支，但本批没有验证 TextZip 输入。
