<script setup lang="ts">
import { ref, computed, onMounted } from "vue";
import { ElMessage } from "element-plus";
import axios from 'axios';

// --- 配置与状态 ---
const wazuhUser = import.meta.env.VITE_WAZUH_SERVER_API_USERNAME;
const wazuhPass = import.meta.env.VITE_WAZUH_SERVER_API_PASSWORD;
const AUTH_PAYLOAD = btoa(`${wazuhUser}:${wazuhPass}`);
const token = ref("");

const searchText = ref("");
const rules = ref<any[]>([]);
const loading = ref(false);
const detailVisible = ref(false);

const currentRule = ref<any>(null);      // 存储当前选中的规则 JSON 信息
const currentRuleXml = ref("");          // 存储从 API 获取的原始 XML 字符串

const showPanel = ref(false);
const searchStage = ref<'field' | 'operator' | 'value'>('field');
const selectedField = ref("");
const selectedOperator = ref("");

// 字段映射
const fieldOptions = [
  { label: 'id', display: 'id', desc: 'Rule ID', color: '#e06c75' },
  { label: 'level', display: 'level', desc: 'Severity level', color: '#d19a66' },
  { label: 'groups', display: 'group', desc: 'Rule group', color: '#c678dd' },
  { label: 'filename', display: 'file', desc: 'XML Filename', color: '#98c379' }
];

const operators = [{ label: '=', desc: 'equality' }, { label: '>', desc: 'gt' }, { label: '<', desc: 'lt' }];

const valueSuggestions = computed(() => {
  const field = selectedField.value;
  if (selectedField.value === 'level') return ['3', '5', '10', '15'];
  if (field === 'id') {
    // 给出一些常见的规则 ID 起始值作为建议
    return ['100', '500', '1000', '2501', '92145'];
  }
  return ['sysmon', 'windows', 'sshd'];
});

// --- 核心方法：认证 ---
const authenticate = async () => {
  try {
    const res = await axios.get('/wazuh-api/security/user/authenticate', {
      headers: { 'Authorization': `Basic ${AUTH_PAYLOAD}` }
    });
    token.value = res.data.data.token;
    return true;
  } catch (err) {
    ElMessage.error("Wazuh 认证失败");
    return false;
  }
};

// --- 获取规则列表 ---
const fetchRules = async (isRetry = false) => {
  if (!token.value) {
    const success = await authenticate();
    if (!success) return;
  }

  loading.value = true;
  const hasLogic = /(=|>|<)/.test(searchText.value);
  const params: any = { limit: 50, sort: '-level' };
  if (hasLogic) params.q = searchText.value;
  else if (searchText.value.trim()) params.search = searchText.value;

  try {
    const res = await axios.get('/wazuh-api/rules', {
      params,
      headers: { 'Authorization': `Bearer ${token.value}` }
    });
    rules.value = res.data.data?.affected_items || [];
  } catch (err: any) {
    if (err.response?.status === 401 && !isRetry) {
      token.value = "";
      await fetchRules(true);
    } else {
      ElMessage.error("获取列表失败");
    }
  } finally {
    loading.value = false;
  }
};

const fetchRuleXml = async (rule: any) => {
  loading.value = true;
  currentRule.value = rule;
  currentRuleXml.value = ""; 

  try {
    const res = await axios.get(`/wazuh-api/rules/files/${rule.filename}`, {
      headers: { 
        'Authorization': `Bearer ${token.value}`,
        'Accept': 'application/xml, text/plain' 
      }
    });

    // 如果返回的是纯文本字符串且不以 { 开头，说明拿到了原始 XML
    if (typeof res.data === 'string' && !res.data.trim().startsWith('{')) {
      currentRuleXml.value = res.data;
    } else {
      // 否则说明拿到的是 JSON 结构，需要手动还原 XML
      const jsonData = typeof res.data === 'string' ? JSON.parse(res.data) : res.data;
      const content = jsonData.data?.affected_items?.[0];
      
      if (content) {
        currentRuleXml.value = jsonToXml(content);
      }
    }
    
    detailVisible.value = true;
  } catch (err: any) {
    console.error("XML获取失败:", err);
    ElMessage.error("获取规则内容失败");
  } finally {
    loading.value = false;
  }
};

/**
 * 强力还原函数：将 Wazuh 的 JSON 对象重新构造为标准的 XML 字符串
 */
const jsonToXml = (obj: any) => {
  let xml = '<?xml version="1.0" encoding="UTF-8"?>\n';

  // 辅助函数：确保数据始终以数组形式处理，解决 .forEach 报错
  const ensureArray = (item: any) => {
    if (!item) return [];
    return Array.isArray(item) ? item : [item];
  };

  // 1. 处理变量 (var)
  ensureArray(obj.var).forEach((v: any) => {
    xml += `<var name="${v['@name']}">${v['#text'] || ''}</var>\n`;
  });

  // 2. 处理组 (group)
  ensureArray(obj.group).forEach((g: any) => {
    xml += `<group name="${g['@name']}">\n`;
    
    // 3. 处理组内的规则 (rule)
    ensureArray(g.rule).forEach((r: any) => {
      xml += `  <rule id="${r['@id']}" level="${r['@level']}">\n`;
      
      // 遍历规则内的所有属性（如 match, decoded_as, description 等）
      Object.keys(r).forEach(key => {
        if (key.startsWith('@')) return; // 跳过属性标签
        
        const value = r[key];
        ensureArray(value).forEach(val => {
          if (typeof val === 'object') {
            // 处理带属性的标签，如 <field name="user">
            const attr = val['@name'] ? ` name="${val['@name']}"` : '';
            xml += `    <${key}${attr}>${val['#text'] || ''}</${key}>\n`;
          } else {
            xml += `    <${key}>${val}</${key}>\n`;
          }
        });
      });
      
      xml += `  </rule>\n`;
    });
    
    xml += `</group>\n\n`;
  });

  return xml;
};


// --- 交互逻辑 ---
const handleSelect = (item: any) => {
  if (searchStage.value === 'field') {
    selectedField.value = item.label;
    searchText.value = item.label;
    searchStage.value = 'operator';
  } else if (searchStage.value === 'operator') {
    selectedOperator.value = item.label;
    searchText.value = `${selectedField.value}${item.label}`;
    searchStage.value = 'value';
  } else if (searchStage.value === 'value') {
    searchText.value = `${selectedField.value}${selectedOperator.value}${item}`;
    showPanel.value = false;
    searchStage.value = 'field';
    fetchRules();
  }
};

const getLevelColor = (level: any) => {
  const l = Number(level);
  if (l >= 12) return '#f5023d';
  if (l >= 8) return '#e3b337';
  return '#31ABE3';
};

onMounted(() => fetchRules());
</script>

<template>
  <div class="rules_container">
    <!-- 搜索栏 -->
    <div class="search_group">
      <div class="input_container">
        <div class="input_wrapper" :class="{ 'focus': showPanel }">
          <span class="prefix">🔍</span>
          <input 
            v-model="searchText" 
            placeholder="输入查询 (如 level>10) 或使用下拉构造..."
            @focus="showPanel = true"
            @keyup.enter="fetchRules()"
          />
          <button v-if="searchText" class="clear" @click="searchText=''; searchStage='field'">×</button>
        </div>

        <!-- 交互式构造面板 -->
        <div v-if="showPanel" class="interactive_panel">
          <template v-if="searchStage === 'field'">
            <div class="p_item action" @click="showPanel=false; fetchRules()"><strong>Search</strong><span>执行当前查询</span></div>
            <div v-for="f in fieldOptions" :key="f.label" class="p_item" @click="handleSelect(f)">
              <b :style="{color: f.color}">⊚ {{ f.display }}</b> <span>{{ f.desc }}</span>
            </div>
          </template>

          <template v-else-if="searchStage === 'operator'">
            <div v-for="op in operators" :key="op.label" class="p_item" @click="handleSelect(op)">
              <b>{{ op.label }}</b> <span>{{ op.desc }}</span>
            </div>
          </template>

          <template v-else-if="searchStage === 'value'">
            <div v-for="v in valueSuggestions" :key="v" class="p_item" @click="handleSelect(v)">
              <b>{{ v }}</b> <span>建议值</span>
            </div>
          </template>
        </div>
      </div>
      <button class="refresh_btn" @click="fetchRules(false)">刷新</button>
    </div>

    <!-- 列表展示 -->
    <div class="rule_list" v-loading="loading" element-loading-background="rgba(0, 0, 0, 0.7)">
      <div v-for="rule in rules" :key="rule.id" class="rule_card" @click="fetchRuleXml(rule)">
        <div class="header">
          <span class="id">ID: {{ rule.id }}</span>
          <span class="lvl" :style="{color: getLevelColor(rule.level)}">Level {{ rule.level }}</span>
        </div>
        <div class="body">{{ rule.description }}</div>
        <div class="footer_info">{{ rule.filename }}</div>
      </div>
    </div>

    <!-- XML 详情弹窗 -->
    <el-dialog 
      v-model="detailVisible" 
      :title="`规则源码: ${currentRule?.filename}`" 
      width="75%"
      destroy-on-close
    >
      <div class="xml_viewer">
        <div class="xml_header">
          <span>Path: {{ currentRule?.relative_dirname }}/{{ currentRule?.filename }}</span>
        </div>
        <pre class="xml_content">{{ currentRuleXml }}</pre>
      </div>
      <template #footer>
        <button class="close_btn" @click="detailVisible = false">关闭预览</button>
      </template>
    </el-dialog>
  </div>
</template>

<style scoped lang="scss">
.rules_container { padding: 15px; height: 100vh; display: flex; flex-direction: column; background: #0a0a0a; color: #eee; }

.search_group { display: flex; gap: 10px; margin-bottom: 15px; position: relative; }
.input_container { flex: 1; position: relative; }
.input_wrapper {
  display: flex; align-items: center; background: #1a1a1a; border: 1px solid #333; border-radius: 4px; padding: 0 10px;
  &.focus { border-color: #31ABE3; box-shadow: 0 0 8px rgba(49, 171, 227, 0.2); }
  input { flex: 1; background: transparent; border: none; padding: 12px; color: #fff; outline: none; font-family: 'Fira Code', monospace; }
  .clear { background: none; border: none; color: #666; cursor: pointer; font-size: 18px; }
}

.interactive_panel {
  position: absolute; top: 105%; left: 0; width: 100%; background: #151515; border: 1px solid #31ABE3; z-index: 1000;
  max-height: 300px; overflow-y: auto; border-radius: 4px; box-shadow: 0 10px 20px rgba(0,0,0,0.5);
  .p_item {
    padding: 12px 15px; display: flex; justify-content: space-between; cursor: pointer; border-bottom: 1px solid #222;
    &:hover { background: #222; }
    b { font-family: monospace; }
    span { color: #555; font-size: 12px; }
    &.action { background: #1a1a1a; color: #31ABE3; border-bottom: 2px solid #31ABE3; }
  }
}

.rule_list { flex: 1; overflow-y: auto; padding-right: 5px; }
.rule_card {
  background: #161616; padding: 15px; margin-bottom: 10px; border-left: 4px solid #31ABE3; cursor: pointer; transition: 0.2s;
  &:hover { background: #202020; transform: translateX(4px); }
  .header { display: flex; justify-content: space-between; margin-bottom: 8px; .id { color: #31ABE3; font-weight: bold; font-family: monospace; } }
  .body { font-size: 14px; color: #bbb; line-height: 1.4; margin-bottom: 8px; }
  .footer_info { font-size: 11px; color: #555; text-align: right; font-style: italic; }
}

.xml_viewer {
  background: #1e1e1e; border-radius: 4px; overflow: hidden; border: 1px solid #333;
  .xml_header { background: #2d2d2d; padding: 8px 15px; font-size: 12px; color: #888; border-bottom: 1px solid #111; }
  .xml_content {
  margin: 0; 
  padding: 20px; 
  
  /* 更新这里：改为你要求的蓝色 */
  color: #31ABE3; 
  
  font-family: 'Consolas', 'Monaco', monospace;
  font-size: 14px; 
  line-height: 1.6; 
  white-space: pre-wrap; 
  word-break: break-all;
  max-height: 60vh; 
  overflow-y: auto;
}
}

.refresh_btn { background: #31ABE3; border: none; color: #fff; padding: 0 20px; border-radius: 4px; cursor: pointer; font-weight: bold; }
.close_btn { background: #444; border: none; color: #fff; padding: 10px 25px; border-radius: 4px; cursor: pointer; &:hover { background: #555; } }

:deep(.el-dialog) { 
  background: #151515 !important; 
  .el-dialog__title { color: #31ABE3; font-weight: bold; }
  .el-dialog__header { border-bottom: 1px solid #222; margin-right: 0; padding-bottom: 15px; }
}
</style>