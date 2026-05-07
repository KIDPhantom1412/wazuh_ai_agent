<script setup lang="ts">
import { ref, reactive, onMounted, computed } from "vue";
import { ElMessage } from "element-plus";
import axios from 'axios';

const indexerUser = import.meta.env.VITE_WAZUH_INDEXER_USER;
const indexerPass = import.meta.env.VITE_WAZUH_INDEXER_PASSWORD;
const INDEXER_AUTH = btoa(`${indexerUser}:${indexerPass}`);

// --- 状态管理 ---
const searchText = ref("");
const allFields = ref<string[]>([]);
const showPanel = ref(false);
const logs = ref<any[]>([]);
const loading = ref(false);

// --- 详情弹窗状态 ---
const detailVisible = ref(false);
const currentLog = ref<any>(null);

// 1. 获取字段字典 (Mapping)
const fetchAvailableFields = async () => {
  try {
    const res = await axios.get('/wazuh-indexer/wazuh-alerts-*/_mapping', {
      headers: { 'Authorization': `Basic ${INDEXER_AUTH}` }
    });
    const fields: string[] = [];
    const extractFields = (obj: any, path = '') => {
      for (const key in obj) {
        const fullPath = path ? `${path}.${key}` : key;
        if (obj[key].properties) extractFields(obj[key].properties, fullPath);
        else fields.push(fullPath);
      }
    };
    const firstIndex = Object.keys(res.data)[0];
    extractFields(res.data[firstIndex].mappings.properties);
    allFields.value = Array.from(new Set(fields));
  } catch (err) { console.error("字段加载失败", err); }
};

// 2. 字段搜索建议逻辑
const filteredFields = computed(() => {
  if (!searchText.value) return [];
  const words = searchText.value.split(/\s+/);
  const lastWord = words[words.length - 1].toLowerCase();
  if (!lastWord) return [];
  return allFields.value.filter(f => f.toLowerCase().includes(lastWord)).slice(0, 8);
});

const selectField = (fieldName: string) => {
  const words = searchText.value.split(/\s+/);
  words[words.length - 1] = `${fieldName}: `;
  searchText.value = words.join(' ');
  showPanel.value = false;
};

// 3. 执行查询
const getData = async () => {
  if (!searchText.value.includes(':')) {
    ElMessage.info("请完成查询表达式 (例如 agent.id: 001)");
    return;
  }
  loading.value = true;
  const [field, value] = searchText.value.split(':').map(s => s.trim());
  try {
    const res = await axios.post('/wazuh-indexer/wazuh-alerts-*/_search', {
      size: 30,
      sort: [{ "timestamp": "desc" }],
      query: { match_phrase: { [field]: value } }
    }, {
      headers: { 'Authorization': `Basic ${INDEXER_AUTH}`, 'Content-Type': 'application/json' }
    });
    // 注意：这里我们将整个 item._source 存下来供详情查看
    logs.value = res.data.hits.hits;
  } catch (err) { ElMessage.error("查询失败"); }
  finally { loading.value = false; }
};

// 4. 打开详情弹窗
const openDetail = (logSource: any) => {
  currentLog.value = logSource;
  detailVisible.value = true;
};

onMounted(() => { fetchAvailableFields(); });
</script>

<template>
  <div class="right_bottom">
    <div class="search_group">
      <div class="input_container">
        <input 
          v-model="searchText" 
          placeholder="输入字段关键词 (如 data.win...)"
          @focus="showPanel = true"
          @keyup.enter="getData"
        />
        <div v-if="showPanel && filteredFields.length > 0" class="field_dropdown">
          <div v-for="field in filteredFields" :key="field" class="field_item" @mousedown="selectField(field)">
            <span class="icon">f</span> {{ field }}
          </div>
        </div>
      </div>
      <button class="update_btn" @click="getData" :disabled="loading">
        {{ loading ? '...' : '查询' }}
      </button>
    </div>

    <div class="log_list">
      <div v-if="logs.length === 0" class="empty_tip">等待查询指令...</div>
      <div 
        v-for="item in logs" 
        :key="item._id" 
        class="log_card" 
        @click="openDetail(item._source)"
      >
        <div class="card_header">
          <span class="time">{{ new Date(item._source.timestamp).toLocaleString() }}</span>
          <span class="level" :style="{ color: item._source.rule.level >= 12 ? '#f5023d' : '#e3b337' }">
            Level {{ item._source.rule.level }}
          </span>
        </div>
        <div class="card_body">{{ item._source.rule.description }}</div>
        <div class="card_footer">点击查看完整详情</div>
      </div>
    </div>

    <el-dialog
      v-model="detailVisible"
      title="告警日志完整详情"
      width="60%"
      destroy-on-close
      custom-class="dark_dialog"
    >
      <div class="detail_content">
        <pre v-if="currentLog">{{ JSON.stringify(currentLog, null, 2) }}</pre>
      </div>
      <template #footer>
        <button class="close_btn" @click="detailVisible = false">确 定</button>
      </template>
    </el-dialog>
  </div>
</template>

<style scoped lang="scss">
.right_bottom {
  box-sizing: border-box;
  padding: 0 16px;
  height: 100%;
  display: flex;
  flex-direction: column;
}

// 搜索栏样式保持之前风格
.search_group {
  display: flex; gap: 10px; margin-bottom: 15px; position: relative;
  .input_container {
    flex: 1; position: relative;
    input {
      width: 100%; background: rgba(0, 0, 0, 0.5); border: 1px solid #31ABE3;
      border-radius: 4px; padding: 8px 12px; color: #fff; outline: none; font-family: monospace;
    }
  }
  .update_btn {
    background: #31ABE3; border: none; color: white; padding: 0 15px;
    border-radius: 4px; cursor: pointer; font-weight: bold;
    &:disabled { opacity: 0.5; }
  }
}

.field_dropdown {
  position: absolute; top: 100%; left: 0; width: 100%; background: #1a222a;
  border: 1px solid #31ABE3; z-index: 999; max-height: 200px; overflow-y: auto;
  .field_item {
    padding: 8px 12px; color: #eee; cursor: pointer; font-size: 13px;
    &:hover { background: rgba(49, 171, 227, 0.3); }
    .icon { color: #31ABE3; margin-right: 8px; font-weight: bold; }
  }
}

// 日志卡片样式
.log_list {
  flex: 1; overflow-y: auto;
  &::-webkit-scrollbar { width: 4px; }
  &::-webkit-scrollbar-thumb { background: #31ABE3; }
  .log_card {
    background: rgba(255, 255, 255, 0.03); border-radius: 4px; padding: 12px;
    margin-bottom: 10px; border-left: 3px solid #31ABE3; cursor: pointer;
    transition: transform 0.2s;
    &:hover { background: rgba(255, 255, 255, 0.08); transform: translateX(5px); }
    .card_header {
      display: flex; justify-content: space-between; font-size: 12px; margin-bottom: 8px;
      .time { color: #aaa; }
    }
    .card_body { font-size: 13px; color: #eee; line-height: 1.5; }
    .card_footer { font-size: 10px; color: #31ABE3; margin-top: 10px; text-align: right; opacity: 0.7; }
  }
}

// 弹窗深度样式定制
:deep(.el-dialog) {
  background: #1a222a !important;
  border: 1px solid #31ABE3;
  .el-dialog__title { color: #31ABE3; }
  .el-dialog__body { color: #ddd; }
}

.detail_content {
  background: #0d1117;
  padding: 15px;
  border-radius: 4px;
  max-height: 500px;
  overflow-y: auto;
  pre {
    margin: 0;
    font-family: 'Courier New', Courier, monospace;
    font-size: 12px;
    white-space: pre-wrap; // 自动换行
    word-break: break-all;
    color: #a5d6ff; // 科技蓝配色
  }
}

.close_btn {
  background: #31ABE3; border: none; color: #fff;
  padding: 6px 20px; border-radius: 4px; cursor: pointer;
}

.empty_tip { text-align: center; color: #555; padding-top: 50px; }
</style>