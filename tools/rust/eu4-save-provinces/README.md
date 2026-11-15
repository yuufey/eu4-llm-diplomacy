# EU4 存档省份关系读取器

这个 CLI 用固定版本的 Jomini/eu4save 解析文本存档，输出保存日期、版本、玩家、国家标签，以及各省份的 cores、claims 和 discovered_by。它读取存档快照，不读取游戏进程；`claims` 不区分永久宣称，`discovered_by` 也不证明当前 UI 可见。

## 解析方式与边界

vendored Jomini 固定在 commit `8fbd6861f453c719da59daac6970babd9ddc19ac`，MIT 许可保存在 `third_party/jomini/LICENSE.txt`。CLI 用 Jomini 的 `JominiDeserialize` 派生自定义小型 serde 模型读取所需字段；上游 `eu4save` 的 `models.rs` 未修改。

省份序列化键按有符号整数读取。CLI 保留原键为 `serialized_key`，用 `checked_abs()` 得到正数 `province_id`；绝对值溢出、越界或多个原键映射到同一 canonical ID 时，解析失败。`country_tags` 会省略 Jomini 的 `CountryTag::NONE` 哨兵 `---`；省份 cores、claims 和 discovered_by 中的标签原样保留。

代码支持 Jomini `Text` 与 `TextZip` 输入。本批实际解析验证的是 EU4 1.37.4 `Text` 存档；没有实测 `TextZip`。CLI 拒绝 `Binary` 和 `BinaryZip`，因为此构建没有配置 EU4 二进制 token resolver。

CLI 在读取前限制压缩文件大小为 128 MiB，并以 128 MiB 限制 Jomini 报告的展开大小；标准输出 JSON 最大为 32 MiB。超过限制或输入在读取期间变化时，CLI 写错误到 stderr 并返回非零状态。

## 构建与信任文件

从仓库根目录运行标准命令：

```powershell
cargo build --release --jobs 1 --manifest-path tools/rust/eu4-save-provinces/Cargo.toml
```

本批使用隔离 Rust 工具链，未修改全局 PATH 或用户配置：

- 工具链目录：[work/deps/jomini-rust-toolchain-104](../../../work/deps/jomini-rust-toolchain-104/)
- 隔离安装器与安装记录：[rustup-init.exe](../../../work/deps/jomini-rust-toolchain-104/rustup-init.exe)、[rustup-install.log](../../../work/runtime/information-save-interests-20261102-001/toolchain-001/rustup-install.log)
- 构建目标目录：`work/deps/jomini-rust-toolchain-104/build-target-revision2`
- 单作业、0.5 秒采样构建记录：[build_monitored_005.py](../../../work/runtime/information-save-interests-20261102-001/toolchain-001/build_monitored_005.py)；[构建收据](../../../work/runtime/information-save-interests-20261102-001/toolchain-001/cargo-build-receipt-005.json)
- 当前可执行文件：[eu4-save-provinces.exe](../../../work/deps/jomini-rust-toolchain-104/eu4-save-provinces.exe)
- 受信 parser manifest：[adapter-manifest.json](adapter-manifest.json)
- 本批 manifest 生成原件：[create_adapter_manifest_002.py](../../../work/runtime/information-save-interests-20261102-001/toolchain-001/create_adapter_manifest_002.py)
- 本批实际文本存档解析与核对收据：[parser-readiness-001.json](../../../work/runtime/information-save-interests-20261102-001/toolchain-001/parser-readiness-001.json)

本批构建只在 PowerShell 当前进程设置 `CARGO_HOME`、`RUSTUP_HOME` 和 `CARGO_TARGET_DIR`，再运行上面的命令：

```powershell
$repo = (Resolve-Path '.').Path
$env:CARGO_HOME = Join-Path $repo 'work/deps/jomini-rust-toolchain-104/cargo-home'
$env:RUSTUP_HOME = Join-Path $repo 'work/deps/jomini-rust-toolchain-104/rustup-home'
$env:CARGO_TARGET_DIR = Join-Path $repo 'work/deps/jomini-rust-toolchain-104/build-target-revision2'
$env:PATH = (Join-Path $env:CARGO_HOME 'bin') + ';' + $env:PATH
cargo build --release --jobs 1 --manifest-path tools/rust/eu4-save-provinces/Cargo.toml
```

`adapter-manifest.json` 固定 CLI 二进制及其源码哈希。重新编译或修改任何受信源码后，必须重新计算并更新 manifest 中的二进制和源码哈希；不能沿用旧哈希。当前 manifest 记录 77 个源码 pin。
