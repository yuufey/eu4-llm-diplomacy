[English](Readme_EN.md) | [简体中文](Readme.md)

# EU4 LLM Diplomacy

This project brings Model Context Protocol (MCP) support to **Europa Universalis IV**. Human players keep control of their own countries while sharing a campaign with several large language models (LLMs) and interacting with them through diplomacy.

The long-term goal is for LLMs to handle diplomacy and other strategic decisions for selected AI-controlled countries where the choices matter and the micromanagement is light. Europa Universalis IV's native AI continues to run the remaining game systems.

The idea is to negotiate directly with LLM-controlled countries in writing. Promise concessions, issue threats, discuss alliances, negotiate peace, deceive your rivals, or break your word. We want diplomacy to feel richer and more like the real thing. We also hope LLM-controlled countries will be better at planning ahead. Even as a spectator, it should be fun to pit different models against one another in the same campaign.

The game exposes very few diplomatic actions to external tools, so we use reverse engineering, DLL injection, and runtime hooking to make those actions available to LLMs.

Most of the technical work is complete, and the project has moved into playtesting and refinement. Clone this development repository to use the separate [playtesting repository](https://github.com/yuufey/eu4-llm-diplomacy-tests).

## Feature Overview

### Game Information

A model can ask how much manpower its country has left, when a truce with a neighbor expires, or which mission requirements still need to be met. It can combine recurring queries into scheduled reports or subscribe to supported events such as battle results and truce expirations. Information about other countries depends on what the observing country can see and what the interface can read.

- [Countries and Domestic Affairs](docs/信息导出/接口/国家与国内/) — Treasury, monthly income and expenses, armies and navies, manpower, and governing capacity.
- [Relations and Diplomacy](docs/信息导出/接口/关系与外交/) — Opinion in both directions, truce dates, coalitions, diplomats, and incoming diplomatic offers.
- [Wars and Battle Reports](docs/信息导出/接口/战争与战报/) — War participants, war score, war participation, and losses from past battles.
- [Missions](docs/信息导出/接口/任务/) — Mission tree branches, prerequisites, target provinces, and rewards.
- [Trade and Provinces](docs/信息导出/接口/贸易与省份/) — Province ownership, cores and claims, trade node value, and each country's trade power.
- [Game Mechanics and Religion](docs/信息导出/接口/机制与宗教/) — Rulers and succession, Holy Roman Empire electors and reforms, the Papacy, and religious schools.

### Diplomatic Actions

A model can check whether the game currently allows an action on behalf of a country it is authorized to control. Where applicable, it can see whether the other country is likely to accept and which factors affect that decision. It can then submit the action and check the actual outcome.

- [Relations and Diplomacy](docs/外交操作/接口/关系与外交/) — Propose alliances, improve relations, arrange royal marriages, build spy networks, send gifts, and spend favors.
- [War and Peace](docs/外交操作/接口/战争与战报/) — Choose a casus belli and war participants, check war score, preview the consequences of peace terms, and propose peace.

### Maps

A model can view overview, regional, and local maps from the perspective of the country it controls. The military layer can show army sizes and positions, as well as the locations, levels, and siege progress of forts belonging to countries at war. The maps simplify visual detail to make them easier for LLMs to interpret. While the game is running, the service can also export images at all three scales and province ownership data at regular in-game monthly intervals. [Map Export Guide](docs/地图功能/地图导出接口使用说明.md)

### Scheduled Decisions and Game Speed

The test environment can generate strategic briefings for the controlled country at intervals measured in game days and deliver them to the same Codex session for further decisions. With permission to control game speed, the model can also pause the game or change its speed. [Strategic Briefing Test Record](logs/2026-11-21战略简报触发Codex回合.md) · [Unified Game Service Guide](docs/共用开发/统一游戏服务使用说明.md)

**The Codex desktop app cannot currently add briefings to an active session in real time. We are considering Codex CLI or another approach.**

## Features Still to Build or Test

- An in-game interface for chatting with an LLM. A prototype exists and has yet to be committed.
- Multiple LLMs playing together and communicating with one another.
- LLM input into warfare, such as choosing where to focus an offensive, adjusting aggressiveness, and influencing how readily armies group together.
- LLM control over military spending, selection of idea groups, and technology advancement.
- And more.

## Getting Started

1. Clone this repository or give its URL to your agent. Also provide the EU4 installation directory containing `eu4.exe` and the user data directory, usually `C:\Users\<your username>\Documents\Paradox Interactive\Europa Universalis IV`. The agent can help configure your environment, build the project, and reproduce experiments.
2. To set it up yourself, clone the repository, follow the [Path Configuration Guide](docs/共用开发/路径配置.md), then work through the [Reproduction Guide](docs/共用开发/人工实验与日志读取流程.md).

> [!WARNING]
> The project relies on reverse-engineered runtime interfaces, DLL injection, and hooking. Compatibility with other game versions is not guaranteed. Experimental builds can crash the game, corrupt saves, or cause other unexpected behavior. Use disposable test saves or make sure you have reliable backups.

## Contributing and Playtesting

You can help by testing how your model plays and sharing feedback, implementing or improving a feature, or suggesting changes to the architecture, implementation, or features we have overlooked. The [playtesting repository](https://github.com/yuufey/eu4-llm-diplomacy-tests) is the recommended starting point for testing a model.

If you are interested, you can do any of the following.

1. Leave me your contact details!
2. Open a GitHub issue to discuss an idea or an experiment result.
3. Join a discussion in an existing issue.
4. Fork the repository and open a pull request.
5. Submit a small reproduction case or documentation improvement.
6. And more.

## Disclaimer

This is an unofficial modding and research project for Europa Universalis IV.

Europa Universalis IV, Paradox Interactive, and all related trademarks, game assets, executable code, and other intellectual property belong to Paradox Interactive AB and/or their respective rights holders.

This project has no affiliation with Paradox Interactive AB and has received no authorization, sponsorship, or endorsement from the company.

The repository license applies only to original code and documentation created by the project's contributors. It grants no rights to Europa Universalis IV, its executable files, game data, game assets, or any other third-party intellectual property.

## Technical and Security Notice

This project uses DLL injection, runtime hooking, and internal game interfaces identified through reverse engineering to extend Europa Universalis IV for single-player modding and research.

Debuggers, modding frameworks, security tools, and malware can all use these techniques. Antivirus or endpoint security software may therefore flag the project's binaries or injector as suspicious.

We recommend building the project from the source code in this repository. Obtain precompiled binaries only from this repository's official releases.

The native bridge depends on the game version. A Europa Universalis IV update can invalidate internal addresses, data structures, or hook locations and cause game crashes, save corruption, or other unexpected behavior.

## Intended Use

This project is intended only for local, single-player Europa Universalis IV modding and research.

The project excludes the following uses.

- Bypassing DRM or game ownership checks.
- Unlocking, circumventing, or bypassing paid DLC restrictions.
- Interfering with Paradox or third-party online services.
- Obtaining other users' credentials or private information.
- Gaining an unfair advantage in multiplayer games.

## License

Unless otherwise stated, the original source code in this repository is licensed under the MIT License.

Third-party components and related intellectual property remain subject to their respective licenses and terms of use.
