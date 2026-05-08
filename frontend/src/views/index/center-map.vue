<template>
  <div class="topo-container">
    <!-- 顶部状态栏 -->
    <div class="header">
      <div class="title">Wazuh 威胁拓扑</div>
      <div class="status-info">
        <span class="dot active"></span> 运行中 (每30s刷新)
        <button @click="fetchTopoData" class="refresh-btn">立即刷新</button>
      </div>
    </div>

    <!-- 图表容器 -->
    <div ref="containerRef" class="x6-graph"></div>

    <!-- 底部图例 -->
    <div class="legend">
      <div class="item"><span class="box manager"></span> 管理中心 (Manager)</div>
      <div class="item"><span class="box active"></span> 正常 (Active)</div>
      <div class="item"><span class="box threat"></span> 存在威胁 (Threat)</div>
      <div class="item"><span class="box offline"></span> 离线 (Disconnected)</div>
    </div>

    <!-- 加载遮罩 -->
    <div v-if="loading" class="loading-mask">数据加载中...</div>
  </div>
</template>

<script setup lang="ts">
import { onMounted, onUnmounted, ref, nextTick } from 'vue';
import { Graph } from '@antv/x6';
import axios from 'axios';

// --- 配置区 ---
const TOPOLOGY_API_URL = import.meta.env.VITE_TOPOLOGY_API_URL?.trim() || 'http://127.0.0.1:8000/api/topo';
const TOPOLOGY_MOCK_URL = '/topology/agents_topo_data.json';
const REFRESH_INTERVAL = 30000; // 30秒自动刷新一次

const containerRef = ref<HTMLElement | null>(null);
const loading = ref(false);
let graph: Graph | null = null;
let timer: any = null;

// 1. 初始化画布
const initGraph = () => {
  if (!containerRef.value || graph) return;
  
  graph = new Graph({
    container: containerRef.value,
    autoResize: true,
    background: { color: '#0b0f1a' }, // 深色背景
    panning: true, // 支持拖拽
    mousewheel: true, // 支持滚轮缩放
    grid: {
      size: 10,
      visible: true,
      type: 'dot',
      args: { color: '#1a1f2e', thickness: 1 },
    },
  });
};

// 2. 获取数据并渲染
const fetchTopoData = async () => {
  if (loading.value) return;
  loading.value = true;
  
  try {
    const res = await axios.get(TOPOLOGY_API_URL);
    renderTopology(res.data);
  } catch (err) {
    console.warn('实时拓扑接口不可用，回退到内置示例数据。', err);
    try {
      const mockRes = await axios.get(TOPOLOGY_MOCK_URL);
      renderTopology(mockRes.data);
    } catch (mockErr) {
      console.error("拓扑数据获取失败:", mockErr);
    }
  } finally {
    loading.value = false;
  }
};

// 3. 渲染逻辑
const renderTopology = (agents: any[]) => {
  if (!graph) return;
  graph.getNodes().forEach(node => graph!.removeNode(node));
  graph.getEdges().forEach(edge => graph!.removeEdge(edge));
  graph.clearCells();
  // --- 布局参数 ---
  const centerX = containerRef.value?.clientWidth ? containerRef.value.clientWidth / 2 : 400;
  const startY = 80;
  const agentY = 250;
  const gapX = 180; // 节点横向间距

  // --- A. 绘制 Manager 节点 ---
  // 通常 127.0.0.1 或特定名称的是 Manager
  const managerData = agents.find(a => a.ip === '127.0.0.1' || a.name.toLowerCase().includes('manager'));
  const managerId = 'manager-node';

  graph.addNode({
    id: managerId,
    x: centerX - 75,
    y: startY,
    width: 150,
    height: 60,
    label: `MANAGER\n${managerData?.name || 'Wazuh Server'}`,
    attrs: {
      body: { fill: '#1890ff', stroke: '#fff', strokeWidth: 2, rx: 10, ry: 10 },
      label: { fill: '#fff', fontSize: 12, fontWeight: 'bold' }
    }
  });

  // --- B. 绘制其他 Agents ---
  const otherAgents = agents.filter(a => a.ip !== '127.0.0.1' && !a.name.toLowerCase().includes('manager'));
  
  // 计算总宽度以居中对齐
  const totalWidth = (otherAgents.length - 1) * gapX;
  const startX = centerX - totalWidth / 2;

  otherAgents.forEach((agent, index) => {
    const status = String(agent.status).toLowerCase();
    const hasThreat = agent.has_threat === true;

    // 颜色决策树
    let nodeColor = '#555'; // 默认灰色 (离线)
    if (hasThreat) {
      nodeColor = '#ff4d4f'; // 红色 (威胁)
    } else if (status === 'active') {
      nodeColor = '#52c41a'; // 绿色 (在线)
    }

    const nodeId = `agent-${agent.id}`;

    // 添加节点
    graph!.addNode({
      id: nodeId,
      x: startX + (index * gapX) - 65,
      y: agentY,
      width: 130,
      height: 45,
      label: `${agent.name}\n${agent.ip}`,
      attrs: {
        body: {
          fill: nodeColor,
          stroke: hasThreat ? '#fffb8f' : '#fff', 
          strokeWidth: hasThreat ? 3 : 1,
          rx: 5, ry: 5,
        },
        label: { fill: '#fff', fontSize: 10 }
      }
    });

    // 添加连接线
    graph!.addEdge({
      source: managerId,
      target: nodeId,
      connector: { name: 'rounded' },
      attrs: {
        line: {
          stroke: hasThreat ? '#ff4d4f' : '#444',
          strokeWidth: hasThreat ? 2 : 1,
          targetMarker: 'classic',
          dasharray: status !== 'active' ? '5 5' : '0', // 离线节点使用虚线
        }
      }
    });
  });

  // 自动调整视角
  nextTick(() => {
    graph?.centerContent();
  });
};

// --- 生命周期控制 ---
onMounted(() => {
  initGraph();
  fetchTopoData();
  
  // 启动定时轮询
  timer = setInterval(fetchTopoData, REFRESH_INTERVAL);
});

onUnmounted(() => {
  // 组件销毁时必须清理定时器
  if (timer) clearInterval(timer);
  if (graph) {graph.dispose();
              graph=null;
  }
});
</script>

<style scoped>
.topo-container {
  position: relative;
  width: 100%;
  height: 600px;
  background: #0b0f1a;
  border: 1px solid #1a1f2e;
  overflow: hidden;
  color: white;
  font-family: sans-serif;
}

.header {
  position: absolute;
  top: 0;
  width: 100%;
  padding: 15px;
  display: flex;
  justify-content: space-between;
  align-items: center;
  z-index: 10;
  background: rgba(11, 15, 26, 0.8);
}

.title {
  font-size: 18px;
  font-weight: bold;
  letter-spacing: 1px;
}

.status-info {
  font-size: 12px;
  color: #888;
}

.dot {
  display: inline-block;
  width: 8px;
  height: 8px;
  border-radius: 50%;
  margin-right: 5px;
}

.dot.active {
  background: #52c41a;
  box-shadow: 0 0 5px #52c41a;
}

.refresh-btn {
  margin-left: 10px;
  padding: 2px 8px;
  background: #1890ff;
  border: none;
  color: white;
  cursor: pointer;
  border-radius: 4px;
}

.refresh-btn:hover { background: #40a9ff; }

.x6-graph {
  width: 100%;
  height: 100%;
}

.legend {
  position: absolute;
  bottom: 20px;
  left: 20px;
  display: flex;
  gap: 20px;
  background: rgba(255, 255, 255, 0.05);
  padding: 10px 15px;
  border-radius: 4px;
  font-size: 12px;
}

.legend .item { display: flex; align-items: center; }

.box {
  width: 12px;
  height: 12px;
  margin-right: 6px;
  border-radius: 2px;
}

.box.manager { background: #1890ff; }
.box.active { background: #52c41a; }
.box.threat { background: #ff4d4f; }
.box.offline { background: #555; }

.loading-mask {
  position: absolute;
  inset: 0;
  background: rgba(0,0,0,0.5);
  display: flex;
  justify-content: center;
  align-items: center;
  z-index: 20;
}
</style>
