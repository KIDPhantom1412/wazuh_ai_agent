本项目是一个基于 uv 和 LangGraph 构建的 Wazuh AI Agent 项目。

## 项目约定

- 这是一个 uv 项目。添加、移除或升级依赖包时，必须先在 `pyproject.toml` 中声明对应依赖，再通过 uv 同步环境，不要直接绕过项目依赖配置安装包。
- 完成所有编码任务后，记得运行 `uv run pytest` 检查测试结果。
- AI 完成任何 Python 编码任务后，必须格式化和检查代码：先对本次修改过的 Python 文件运行 `uv run black {修改的文件路径}`，再运行 `uv run ruff check . --fix` 自动修复 ruff 能处理的问题。
- 如果 `black` 或 `ruff` 修改了文件，需要重新运行相关测试；影响面较大时运行完整 `uv run pytest`。

## 项目概览

- `src/agents/` 存放主要智能体实现。
- `src/agents/router_agent.py` 是总控路由智能体，负责理解用户意图，并将规则相关任务或攻击溯源任务委派给对应 specialist。
- `src/agents/rule_agent/` 是 Wazuh 规则智能体，负责规则查询、规则生成、规则验证、规则清理等工作流。
- `src/agents/attack_attribution/` 是攻击溯源智能体，负责基于告警、归档日志和 MITRE 知识进行调查分析。
- `src/wazuh_api/` 封装 Wazuh Server API 和 Indexer API 调用，是智能体与 Wazuh 环境交互的主要边界。
- `tests/` 存放 pytest 测试，覆盖 API 封装、路由智能体、规则智能体、攻击溯源智能体等关键行为。

## 快速上手

1. 优先阅读 `pyproject.toml`，确认依赖、测试、black 和 ruff 配置。
2. 修改智能体逻辑前，先查看对应测试文件，理解当前期望行为。
3. 涉及 Wazuh API 时，优先复用 `src/wazuh_api/` 中已有封装；如需新增接口，补充对应测试。
4. 涉及路由行为时，同步检查 `src/agents/router_agent.py` 的工具说明和系统提示词，确保用户请求能被正确委派。
5. 提交前至少运行相关测试；如果改动影响面较大，运行完整 `uv run pytest`。
6. 如果本次改动包含 Python 代码，最后再次确认已执行 `uv run black {修改的文件路径}` 和 `uv run ruff check . --fix`。
