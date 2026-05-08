# 拓扑图路径变更清单

## 后端迁移

| 原路径 | 新路径 | 说明 |
| --- | --- | --- |
| `frontend/server/get_data.py` | `src/service/topology_service.py` | 拓扑图 FastAPI 小后端已迁移到独立的服务层包中。 |
| `frontend/server/` | 已删除 | 前端目录下不再放置后端运行时代码。 |

## 前端配套文件

| 原路径 | 新路径 | 说明 |
| --- | --- | --- |
| `frontend/agents_topo_data.json` | `frontend/public/topology/agents_topo_data.json` | 该文件作为前端回退展示时使用的静态示例数据。 |

## 接口兼容性

- 实时拓扑接口默认仍为 `http://127.0.0.1:8000/api/topo`
- 前端页面在迁移后仍然按照 `/api/topo` 的语义消费拓扑数据
- 当实时后端不可用时，前端会自动回退到 `public/topology/agents_topo_data.json`
