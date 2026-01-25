## Developer Guide

开发者需要实现在开发环境下安装uv。

### 项目结构

```
WAZUH_AI_AGENT
├─src
│  ├─agents
│  ├─core
│  └─wazuh_api
└─tests
```

### 试运行

```bash
cd wazuh_ai_agent
uv run langgrah dev
```

### 测试

测试代码为`./tests/test_*`，基于`pytest`测试框架。

执行测试：

```bash
cd wazuh_ai_agent
uv run --group dev hatch test --all   # 测试所有python版本
uv run --group dev hatch test --cover # 当前测试代码的覆盖率
```

### 格式化

在提交代码之前，格式化代码。

```bash
cd wazuh_ai_agent
uv run black .
uv run ruff check . --fix
```

### 语言

由于一些兼容性问题，请不要在pyproject.toml中写中文（注释也不要用中文）。
开发过程中的日志请用英文，例如

```python
logger.info("Do not use Chinese.")
```