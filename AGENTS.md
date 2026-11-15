## EU4 diplomacy research workflow

- Read `logs/CURRENT.md` before continuing, then follow only the relevant
  evidence links. `HANDOFF.md` is a navigation entry. README files describe
  the project or module and must not be edited for progress or logging.
- Keep current status and execution history in `logs/`. Keep goals, contracts,
  usage, design rationale and acceptance rules in `docs/`. Do not append batch
  narratives to plans, interface documents or README files. Large raw evidence
  remains in the existing ignored `work/runtime/` location.
- Use the root pytest retention policy. Successful `tmp_path` fixtures are
  disposable; preserve failure output and explicitly required evidence outside
  temporary fixture directories. Do not copy whole source/asset trees into each
  case when a bounded fixture is sufficient. Do not create a new runner copy for
  a new batch when the existing runner accepts the required inputs.
- Keep pytest collection limited to the configured test roots or explicit test
  paths. For new runs set `PYTEST_DEBUG_TEMPROOT` to an existing `work/tmp`
  directory and let pytest create its numbered, locked temporary roots. Avoid
  a new permanent `--basetemp` inside every evidence stage, which bypasses
  numbered-root retention. Existing explicit basetemp runners must clean their
  disposable fixtures when finished. Use separate temporary paths for concurrent workers. Release inactive
  diagnostic capture at the end of a run; persistent verbose capture requires a
  defined size/time budget. Required evidence and current installation files
  must be identified before artifact cleanup.
- For native reverse engineering, use the installed REA skill at
  `${USERPROFILE}/.agents/skills/reverse-engineer-anything/SKILL.md` and
  `docs/共用开发/rea-workflow-1375.md`. Local REA source is `${USERPROFILE}/rea`.
  `python tools/rea.py ...` reuses the Codex REA registration for CLI access.
- REA evidence, ordinary disassembly, static inference, and observed runtime
  effects must remain distinct. Keep binary SHA-256, RVA/VA distinction,
  bounded address ranges, and unresolved conditions with each finding.
- Follow `work/AGENTS.md` resource limits. 

## 自动化
agent可自主进行游戏操作，而无需人类帮助或使用computer use。详见开发过程自动化.md。


## 关于subagent
仅限Astra,Sol和Terra模型使用subagent：你可调用 gpt 6 Luna-Max。你负责核心推理、决策和最终整合；对于耗时、重复、机械、可并行或可独立验证的工作，主动委派给 Luna-Max，必要时并行调用多个实例。不要过度思考是否委派：简单任务自己顺手做了，明显的脏活累活直接派出去，并快速检查其结果后继续工作。假如遇到情形：必须需要等subagent返回结果才能继续。那就等着，什么也不做，不用自己跟subagent并行去做。不用和subagent在同一件事上重复劳动，除非怀疑subagent出错。

子代理曾两次 pwsh 全量读取约 350 MB 反汇编，各提交约 9–10 GB 内存，导致换页风暴，系统几乎卡死。应提醒subagent注意。

## 自动化
一般不必使用computer use或人类操控电脑，见开发过程自动化.md。特别地，进入游戏后总会弹出成就提示窗口，其可以使用脚本关闭。
