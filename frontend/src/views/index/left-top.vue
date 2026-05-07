<script setup lang="ts">
import { reactive, ref, onMounted } from "vue";
import axios from 'axios'; // 确保安装了 axios
import CountUp from "@/components/count-up";
import { ElMessage } from "element-plus";

const duration = ref(2);
const state = reactive({
  alarmNum: 0,    // Wazuh 告警个数
  offlineNum: 0,  // Wazuh 离线 Agents
  onlineNum: 0,   // Wazuh 在线 Agents
  totalNum: 0,    // Wazuh 总 Agent 数
});

// --- Wazuh 配置 (建议以后提取到全局) ---
const AUTH_PAYLOAD = btoa('wazuh:OaOl0*64+.eFxzmBsBe5t8*G9xxEY5ye');
const INDEXER_AUTH = btoa('admin:It2bqmagNT.hxelVM9BrhnKwAZ?5Iz6S');

const getWazuhData = async () => {
  try {
    // 1. 获取 Token
    const auth = await axios.get('/wazuh-api/security/user/authenticate', {
      headers: { 'Authorization': `Basic ${AUTH_PAYLOAD}` }
    });
    const token = auth.data.data.token;

    // 2. 获取 Agents 列表
    const agentsRes = await axios.get('/wazuh-api/agents', {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    const agents = agentsRes.data.data.affected_items;

    // 3. 数据映射
    state.totalNum = agents.length;
    state.onlineNum = agents.filter((a: any) => a.status === 'active').length;
    state.offlineNum = state.totalNum - state.onlineNum;

    // --- 核心修改部分：计算本周一零点 (UTC) ---
    const now = new Date();
    const day = now.getDay() || 7; // 获取今天是周几，如果是周日(0)则设为7
    const monday = new Date(now);
    // 设置为本周一
    monday.setDate(now.getDate() - day + 1);
    // 时间归零：00:00:00
    monday.setHours(0, 0, 0, 0);
    const timeStart = monday.toISOString(); // 格式如: 2023-10-23T00:00:00.000Z

    // 4. 获取本周告警总数
    const alertsRes = await axios.post('/wazuh-indexer/wazuh-alerts-*/_search', {
      size: 0,
      query: {
        bool: {
          must: [
            {
              range: {
                timestamp: {
                  gte: timeStart // 大于等于本周一零点
                }
              }
            }
          ]
        }
      }
    }, {
      headers: { 'Authorization': `Basic ${INDEXER_AUTH}` }
    });
    
    state.alarmNum = alertsRes.data.hits.total.value;

  } catch (err: any) {
    ElMessage.error("Wazuh 数据获取失败: " + err.message);
  }
};

onMounted(() => {
  getWazuhData();
  // 可选：设置 60 秒轮询一次
  setInterval(getWazuhData, 60000);
});
</script>

<template>
  <ul class="user_Overview flex">
    <li class="user_Overview-item" style="color: #00fdfa">
      <div class="user_Overview_nums allnum">
        <CountUp :endVal="state.totalNum" :duration="duration" />
      </div>
      <p>监控设备总数</p> </li>
    <li class="user_Overview-item" style="color: #07f7a8">
      <div class="user_Overview_nums online">
        <CountUp :endVal="state.onlineNum" :duration="duration" />
      </div>
      <p>在线数</p>
    </li>
    <li class="user_Overview-item" style="color: #e3b337">
      <div class="user_Overview_nums offline">
        <CountUp :endVal="state.offlineNum" :duration="duration" />
      </div>
      <p>掉线数</p>
    </li>
    <li class="user_Overview-item" style="color: #f5023d">
      <div class="user_Overview_nums laramnum">
        <CountUp :endVal="state.alarmNum" :duration="duration" />
      </div>
      <p>告警个数</p> </li>
  </ul>
</template>

<style scoped lang="scss">
.left-top {
  width: 100%;
  height: 100%;
}

.user_Overview {
  li {
    flex: 1;

    p {
      text-align: center;
      height: 16px;
      font-size: 16px;
    }

    .user_Overview_nums {
      width: 100px;
      height: 100px;
      text-align: center;
      line-height: 100px;
      font-size: 22px;
      margin: 50px auto 30px;
      background-size: cover;
      background-position: center center;
      position: relative;

      &::before {
        content: "";
        position: absolute;
        width: 100%;
        height: 100%;
        top: 0;
        left: 0;
      }

      &.bgdonghua::before {
        animation: rotating 14s linear infinite;
      }
    }

    .allnum {
      &::before {
        background-image: url("@/assets/img/left_top_lan.png");
      }
    }

    .online {
      &::before {
        background-image: url("@/assets/img/left_top_lv.png");
      }
    }

    .offline {
      &::before {
        background-image: url("@/assets/img/left_top_huang.png");
      }
    }

    .laramnum {
      &::before {
        background-image: url("@/assets/img/left_top_hong.png");
      }
    }
  }
}
</style>
