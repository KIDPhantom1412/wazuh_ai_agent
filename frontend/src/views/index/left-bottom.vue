<script setup lang="ts">
import { ref, reactive, onMounted, onBeforeUnmount } from "vue";
import axios from 'axios';

const indexerUser = import.meta.env.VITE_WAZUH_INDEXER_USER;
const indexerPass = import.meta.env.VITE_WAZUH_INDEXER_PASSWORD;
const INDEXER_AUTH = btoa(`${indexerUser}:${indexerPass}`);

const state = reactive({
  alarmData: [] as any[],
});

// 格式化日期函数：将时间戳转为 YYYY-MM-DD HH:mm:ss
const formatDateTime = (timestamp: string) => {
  const date = new Date(timestamp);
  const y = date.getFullYear();
  const m = (date.getMonth() + 1).toString().padStart(2, '0');
  const d = date.getDate().toString().padStart(2, '0');
  const hh = date.getHours().toString().padStart(2, '0');
  const mm = date.getMinutes().toString().padStart(2, '0');
  const ss = date.getSeconds().toString().padStart(2, '0');
  return `${y}-${m}-${d} ${hh}:${mm}:${ss}`;
};

const getWazuhAlerts = async () => {
  try {
    const res = await axios.post('/wazuh-indexer/wazuh-alerts-*/_search', {
      size: 30, // 增加到30条，确保内容足够多以触发滚动
      sort: [{ "timestamp": "desc" }],
      query: {
        range: { "rule.level": { "gte": 10 } }
      }
    }, {
      headers: { 
        'Authorization': `Basic ${INDEXER_AUTH}`,
        'Content-Type': 'application/json'
      }
    });

    state.alarmData = res.data.hits.hits.map((item: any) => {
      const source = item._source;
      return {
        time: formatDateTime(source.timestamp), // 这里改为显示完整年月日
        level: source.rule.level,
        description: source.rule.description,
        agent: source.agent.name
      };
    });
  } catch (err) {
    console.error("数据拉取失败", err);
  }
};

const getLevelColor = (level: number) => {
  if (level >= 13) return '#f5023d'; 
  if (level >= 11) return '#e3b337';
  return '#31ABE3'; 
};

let timer: any = null;
onMounted(() => {
  getWazuhAlerts();
  timer = setInterval(getWazuhAlerts, 20000);
});

onBeforeUnmount(() => {
  if (timer) clearInterval(timer);
});
</script>

<template>
  <div class="alert_container">
    <div class="alert_header flex">
      <div class="header_item flex-15">时刻</div>
      <div class="header_item flex-05">级别</div>
      <div class="header_item flex-1">主机</div>
      <div class="header_item flex-2">描述</div>
    </div>
    
    <div class="scroll_wrapper">
      <div class="scroll_list" :class="{ 'animate_scroll': state.alarmData.length > 5 }">
        <div v-for="(item, index) in [...state.alarmData, ...state.alarmData]" :key="index" class="alert_item flex">
          <div class="item_text time flex-15">{{ item.time }}</div>
          <div class="item_text level flex-05" :style="{ color: getLevelColor(item.level) }">L{{ item.level }}</div>
          <div class="item_text agent flex-1">{{ item.agent }}</div>
          <div class="item_text description flex-2">{{ item.description }}</div>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped lang="scss">
.alert_container {
  width: 100%;
  height: 100%;
  overflow: hidden;
  color: #fff;
  font-size: 12px;

  .flex { display: flex; align-items: center; }
  .flex-05 { flex: 0.5; }
  .flex-1 { flex: 1; }
  .flex-15 { flex: 1.5; }
  .flex-2 { flex: 2; }

  .alert_header {
    background: rgba(49, 171, 227, 0.2);
    padding: 10px 0;
    color: #31ABE3;
    font-weight: bold;
    .header_item { text-align: center; }
  }

  .scroll_wrapper {
    height: calc(100% - 40px);
    overflow: hidden; // 必须隐藏溢出
    position: relative;
  }

  .scroll_list {
    position: absolute;
    width: 100%;
    top: 0;
    left: 0;
  }

  // 无缝滚动动画
  .animate_scroll {
    animation: scroll_up 30s linear infinite; // 30秒走完一个周期
    &:hover {
      animation-play-state: paused; // 鼠标悬停时停止滚动，方便查看
    }
  }

  @keyframes scroll_up {
    0% { transform: translateY(0); }
    100% { transform: translateY(-50%); } // 向上移动一半的高度（因为我们复制了一份数据）
  }

  .alert_item {
    padding: 12px 0;
    border-bottom: 1px solid rgba(255, 255, 255, 0.05);
    .item_text {
      text-align: center;
      padding: 0 5px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    .time { font-family: monospace; font-size: 11px; }
  }
}
</style>