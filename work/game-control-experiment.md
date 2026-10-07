# 游戏控制实验：2026-10-07

载入→推进→保存→改名→重载的五个步骤已实测跑通；单次连续编排仍需从新基线复跑。已验证的外交 v9 保持原样。

重载已验收：PID 30196 自动确认成就提示后载入，玩家 POR，日期原始值 56459040（1445.2.5），speed=0、paused_flag=1，英法战争关联与保存前一致。`runtime/control-save-validation.json` 的 reloaded=true；日志 `runtime/control-reload-native.jsonl`。当前此进程加载 v3，已暂停，无待处理请求。下述“等待重载”是阶段记录，已由本段结果替代。

最新增量：v3 / PID 51736 已稳定载入，实际 `autosave` 文件已生成并改名为 `llm_control_autosave_20261007.eu4`，日期 1445.2.5 / POR，SHA256 `e993124989a765c913cb1bb90e63c319f771ac19fea7ecc2d789c260b599e91e`。原有 autosave、old_autosave、older_autosave 从备份恢复且哈希一致。证据 `runtime/control-save-validation.json`、`runtime/control-save-native.jsonl`。已启动新进程 PID 30196 重载结果，v3 安装及确认请求排队完成；等待前台帧，尚未验收重载。`tools/verify_control_reload.py --pid 30196` 校验文件哈希、玩家、日期、暂停标志和英法战争关联。

首次推进在载入转换期执行，速度字段已变为 4，但随后暂停标志仍为 1，日期未变；重新暂停后再发推进，精确到达目标。外部编排现增加载入后至少 120 个原生帧等待；该编排改进尚未从全新基线完整重跑，不能称为一键闭环。当前单个步骤的成功与完整无人值守验收应区分。

## 已有实测

- control v1 / PID 41212：成就提示的两个原生确认回调执行后载入 POR；用户没有手动确认。日志 `runtime/control-v1-native-41212.jsonl`。
- 从 1445.1.1 精确推进 35 天到 1445.2.5，原始日期 56459040，与用户观察一致。暂停命令返回成功。
- `savegame` 注册在程序内，帮助文字存在；原生调用返回成功，但没有新存档。用户手动输入也无文件。因此它不能作为当前保存流程的有效依据。额外推进 35 天仍未发现文件。
- 现有存档已备份到 `backup/control-llm_control_cycle_20261007`，没有完成重命名或重新载入。

## v2 闪退与 v3 修复候选

v2 / PID 35120 自动确认载入后闪退。崩溃目录为用户数据下 `crashes/eu4_20261007_225053`；异常 RIP 为主模块 +0x7e01e6，RCX=0、RBP=0，位于 gamespeed 使用的 IsPaused。原生日志 `runtime/control-v2-crash-35120.jsonl` 最后为确认回调返回；没有暂停成功或 autosave 执行证据。

原因：v2 新增的载入后立即暂停仅检查了 POR 玩家身份；此时暂停控制对象尚未创建。v3 增加后续帧等待与 gamespeed 原本使用的 server virtual+0x100 访问器就绪检查，返回空指针时继续等待，不执行控制台调用。严格编译通过，PID 51736 已实测载入及实际保存，未再发生该崩溃。

v3 DLL SHA256：E63A56666A49040AAF0B7A8538F9EA6D89FBEFD0A3579A2A44321CE7BD7B8A39。

入口：`tools/start_game_control.py --pid <PID> --confirm-load-warning`，只在全新进程安装。然后 `tools/run_control_save.py --pid <PID> --name llm_control_autosave_20261007.eu4`。脚本备份现有存档，等待精确日期及实际 autosave 文件，处理旧自动存档轮换并核验恢复哈希。默认 autosave 仍是待验证方案，不能以返回成功验收。

当前全屏游戏失去前台会停帧，仍需用户保持前台。下一步先验收 v3 的安全载入，再验证 autosave 的实际文件；保存与重载闭环完成后，才继续游戏内载入和外交官召回。

## 后续功能的静态定位进展

工具 `map_control_candidates.py` 在当前固定二进制中查找字符串及有界 RIP 引用；结果 `runtime/native-control-candidates.json`，候选不等于可调用接口。

- 运行中载入确认框构造 `0x11bdf80`，使用 CONFIRMLOADSAVETITLE/TEXT，vtable `0x1d65b78`。其虚函数 +0x50=`0x11be1a0` 从确认框 +0x1b8 获取载入界面对象，调用 `0x1175ef0`。
- `0x1175ef0` 读取载入界面 +0x3c0 文件名字符串、+0x250 字符串向量、+0x38 server，构建原生加载上下文后调用 `0x5d05b0`，最后调用 server 转换 `0x824840`。前者包含大量卸载与世界重建，不能拿文件名指针直接替代上下文，也不能在帧钩子中未经生命周期验证直接调用。证据 `control-load-confirm-ui.txt`、`control-load-confirm-handler.txt`、`control-load-selected.txt`、`control-load-selected-name.txt`、`control-load-server-transition.txt`。
- 外交官返回提示 ENVOY_DIPLOMATING_RETURN 的引用位于 `0x2583b0–0x259e4a`；这是提示相关线索，尚未找到安全召回命令。证据 `control-envoy-return-ui.txt`。下一步应由提示引用追踪外交官对象/动作分支，再核对真实召回按钮发送的命令，避免直接修改外交官字段。

### 外交官召回候选 v4（仅编译，未安装/验收）

进一步定位 CANCEL_DIPLOMAT_DIALOG_TITLE/DESC 对应处理 `0x12bc660`。这里有两类操作：队列任务用 type=0x363b（vtable 0x1c52fe8），不能误当作实际外交官召回；正在执行的任务弹出确认框（vtable 0x1d72be0），确认虚函数+0x50=`0x12bb850` 构造 size=0x60、type=0x2b22、vtable 0x1c4d770 的命令，+0x50 国家句柄、+0x58 外交官 ID，经原生 transport 发送。

实际命令执行 `0x274d50` 搜索国家+0x1480 的外交官容器，验证外交官可取消与任务 virtual+0x70==1，然后调用 `0x25a3f0(record,-1)`。该函数保留原生返回旅程逻辑，计算/更新开始日期、结束日期及返回状态；不能把召回等同于立即空闲。证据 `control-cancel-diplomat-dialog.txt`、`control-cancel-diplomat-confirm.txt`、`control-diplomat-recall-execute.txt`、`control-diplomat-return-start-full.txt`、`control-diplomat-return-end.txt`。

新增 `native/diplomat-recall.inc` 与独立构建 `native/build-diplomat-recall.ps1`。仅允许测试玩家 POR / 固定 FRA / diplomat ID 0，核对容器、任务类型、原生可取消检查及加载就绪后构造原生命令，通过原生 dispatcher 提交；不直接改外交官字段。一次进程只允许一次成功排队。请求固定文本 `TEST_ONLY FRA diplomat_0\n`，文件 `diplomat-recall.request`。编译通过不代表发送成功、召回成功或返回完成；尚无启动入口，未向当前 v3 进程注入。下一轮须新进程安装并观察 active 2→1→0 和可用外交官数，之后保存/重载确认。原有 v3 和 v9 保留。

最终候选 SHA256：`979C6D11D3AAFCBF6E1406D2048FCEB4BC750A33836CF01124032D0A1CB5FAA9`。运行中载入链的直接调用追踪工具为 `trace_control_calls.py`；已确认点击处理器 `0x1175580` 创建运行中确认框。下次从该界面上下文及选中文件对象继续验证，不应跳过原生界面选择校验。

## POR 在 FRA 改善关系的外交官召回：v5 已实测

用户主动布置测试现场：POR 外交官0在FRA改善关系，1号4天返回，2号8天返回。只读核对为 active `[2,1,1]`、玩家 POR、日期 1445.2.5。这与 v4 固定 FRA 自身外交官的目标不同，故新增独立 v5，保留旧 DLL。

先在原 PID 30196 以 autosave 保存现场、改名 `llm_control_por_recall_before_20261007.eu4`（SHA256 `2ff7e74763566eda42b8e511053a01d7151558cb418c415bf85cf8e9b4cd6b32`），恢复原有三份自动存档且哈希一致。重新启动后 PID 48184 安装 `eu4_bridge_control_recall_v5.dll`，自动确认成就提示并暂停。v5 对目标限制为 POR / diplomat0 / recipient FRA，验证原生可取消状态后提交 type 0x2b22 命令。

实测结果：同日期暂停帧中 active 2→1，返回记录结束日期56459328，对应12天；另外两名完整记录未变，仍剩4/8天。不是直接置为空闲。证据 `runtime/por-recall-v5-before.json`、`por-recall-v5-after.json`、`por-recall-v5-validation.json`、`por-recall-v5-native.jsonl`。

结果已保存为 `llm_control_por_recall_after_20261007.eu4`（SHA256 `71485bbdf49d7600ab60d917e89a3674b264216aa81763ae46e8159c5bfa6f18`）。只读解析前后存档，POR diplomats action `[2,1,1]`→`[1,1,1]`，证据 `runtime/por-recall-save-comparison.json`。未重载这个结果，也未推进12天验证最终空闲。

入口：`tools/start_game_control.py --pid <fresh_PID> --confirm-load-warning --recall-candidate`、`tools/test_diplomat_recall.py --pid <PID>`。构建 `native/build-diplomat-recall.ps1` 现在输出 v5；SHA256 `E29E17CB419176573C4AE1E7C087D3A38E6261A75705EA028C8A619EF7B2DB39`。该版本一次进程只接受一次成功召回，不覆盖或混装已加载 DLL。`tools/run_control_save.py --save-only` 支持暂停捕获当前固定1445.2.5测试现场，未推进时间。当前 PID48184已暂停，无待处理请求。

后续应将固定目标推广成有明确国家、外交官ID、任务目标与身份核对的请求；然后验证返回完成/结果重载，并将召回模块整合进未来外交自动化版本。现有已验收 v9 不变。游戏内不重启载入仍只有静态定位，未运行验收。
