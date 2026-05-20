## 前端使用说明

### 前置依赖

- Node.js：`>=20.11`
- pnpm：`>=9`

推荐先启用 `corepack`：

```bash
corepack enable
corepack prepare pnpm@latest --activate
```

### 安装依赖

```bash
cd frontend
pnpm install
```
### 如果pnpm install出现报错的解决办法

```bash
pnpm approve-builds
```

### 启动前端开发服务

```bash
cd frontend
pnpm dev
```

前端默认运行在 `http://127.0.0.1:8112`。

### 一键启动前端

```bash
cd frontend
corepack enable && pnpm install && pnpm dev
```

### 常用命令

```bash
pnpm dev
pnpm build
pnpm preview
pnpm type-check
```

### 拓扑图数据来源

- 拓扑图页面会优先请求实时接口 `http://127.0.0.1:8000/api/topo`
- 如果实时接口不可用，前端会自动回退到内置示例数据 `public/topology/agents_topo_data.json`
- 你也可以通过 `VITE_TOPOLOGY_API_URL` 自定义实时接口地址

建议先从示例文件复制一份本地开发配置：

```bash
copy .env.example .env.development
```

然后按你的实际环境修改 `.env.development`，例如：

```bash
VITE_WAZUH_SERVER_API_HOST=192.168.1.100
VITE_WAZUH_SERVER_API_PORT=55000
VITE_WAZUH_INDEXER_PORT=9200
VITE_TOPOLOGY_API_URL=http://127.0.0.1:8000/api/topo
```

### 启动拓扑图小后端

如果你希望前端显示实时拓扑数据，需要额外启动仓库根目录下的拓扑图小后端。

推荐在项目根目录执行：

```bash
uv run wazuh-topology-api
```

这是因为根目录 [pyproject.toml](file:///d:/workspace/wazuh_ai_agent/pyproject.toml#L32-L33) 已经注册了脚本入口 `wazuh-topology-api`。

如果你更希望显式指定模块或文件，也可以在项目根目录执行以下任一命令：

```bash
uv run python -m service.topology_service
```

```bash
uv run src/service/topology_service.py
```

启动成功后，小后端会监听 `http://127.0.0.1:8000`，并提供 `/api/topo` 接口供前端调用。

完整流程示例：

```bash
# 终端 1：在仓库根目录启动拓扑图小后端
uv run wazuh-topology-api

# 终端 2：启动前端
cd frontend
pnpm install
pnpm dev
```

### 说明

- 只看前端页面时，不要求先配置 Python 虚拟环境
- 需要实时拓扑数据时，才需要在仓库根目录使用 `uv run` 启动小后端
