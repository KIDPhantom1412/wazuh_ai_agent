<script setup lang="ts">
import { ref, reactive, onMounted, onBeforeUnmount } from "vue";
import { graphic } from "echarts/core";
import axios from 'axios';
import { ElMessage } from "element-plus";

// --- 配置信息 (建议后期抽取到全局配置文件) ---
const user = import.meta.env.VITE_WAZUH_INDEXER_USER;
const pass = import.meta.env.VITE_WAZUH_INDEXER_PASSWORD;
const INDEXER_AUTH = btoa(`${user}:${pass}`);

const option = ref({});
const state = reactive({
  lowNum: 0,      // 3-7级
  mediumNum: 0,   // 8-10级
  highNum: 0,     // 11-12级
  criticalNum: 0, // 13级以上
  totalNum: 0,
});

// ECharts 渐变色生成函数
const echartsGraphic = (colors: string[]) => {
  return new graphic.LinearGradient(1, 0, 0, 0, [
    { offset: 0, color: colors[0] },
    { offset: 1, color: colors[1] },
  ]);
};

// 获取 Wazuh 告警分布数据
const getWazuhData = async () => {
  try {
    const res = await axios.post('/wazuh-indexer/wazuh-alerts-*/_search', {
      size: 0,
      aggs: {
        level_distribution: {
          range: {
            field: "rule.level",
            ranges: [
              { from: 3, to: 8, key: "low" },
              { from: 8, to: 11, key: "medium" },
              { from: 11, to: 13, key: "high" },
              { from: 13, key: "critical" }
            ]
          }
        }
      }
    }, {
      headers: { 
        'Authorization': `Basic ${INDEXER_AUTH}`,
        'Content-Type': 'application/json'
      }
    });

    const buckets = res.data.aggregations.level_distribution.buckets;
    
    // 更新响应式数据
    state.lowNum = buckets.find((b: any) => b.key === 'low').doc_count;
    state.mediumNum = buckets.find((b: any) => b.key === 'medium').doc_count;
    state.highNum = buckets.find((b: any) => b.key === 'high').doc_count;
    state.criticalNum = buckets.find((b: any) => b.key === 'critical').doc_count;
    
    state.totalNum = state.lowNum + state.mediumNum + state.highNum + state.criticalNum;

    // 重新渲染图表
    setOption();
  } catch (err: any) {
    console.error("Wazuh Indexer 数据获取失败:", err);
    
  }
};

const setOption = () => {
  option.value = {
    title: {
      top: "center",
      left: "center",
      text: [`{value|${state.totalNum}}`, "{name|总告警}"].join("\n"),
      textStyle: {
        rich: {
          value: {
            color: "#ffffff",
            fontSize: 24,
            fontWeight: "bold",
            lineHeight: 20,
            padding: [4, 0, 4, 0]
          },
          name: {
            color: "#ffffff",
            lineHeight: 20,
          },
        },
      },
    },
    tooltip: {
      trigger: "item",
      backgroundColor: "rgba(0,0,0,.6)",
      borderColor: "rgba(147, 235, 248, .8)",
      textStyle: { color: "#FFF" },
    },
    series: [
      {
        name: "告警严重程度分布",
        type: "pie",
        radius: ["40%", "70%"],
        itemStyle: {
          borderRadius: 6,
          borderColor: "rgba(255,255,255,0)",
          borderWidth: 2,
        },
        label: {
          show: true,
          formatter: "   {b|{b}}   \n   {c|{c}次}   {per|{d}%}   ",
          rich: {
            b: { color: "#fff", fontSize: 12, lineHeight: 26 },
            c: { color: "#31ABE3", fontSize: 14 },
            per: { color: "#31ABE3", fontSize: 14 },
          },
        },
        labelLine: {
          show: true,
          length: 15,
          length2: 20,
          smooth: 0.2,
        },
        data: [
          {
            value: state.lowNum,
            name: "低危(3-7)",
            itemStyle: { color: echartsGraphic(["#0BFC7F", "#A3FDE0"]) },
          },
          {
            value: state.mediumNum,
            name: "中危(8-10)",
            itemStyle: { color: echartsGraphic(["#F4D03F", "#F9E79F"]) },
          },
          {
            value: state.highNum,
            name: "高危(11-12)",
            itemStyle: { color: echartsGraphic(["#F39C12", "#FAD7A0"]) },
          },
          {
            value: state.criticalNum,
            name: "极危(13+)",
            itemStyle: { color: echartsGraphic(["#F4023C", "#FB6CB7"]) },
          },
        ],
      },
    ],
  };
};

// 定时器变量
let timer: any = null;

onMounted(() => {
  getWazuhData();
  // 每 30 秒自动刷新一次数据
  timer = setInterval(getWazuhData, 30000);
});

onBeforeUnmount(() => {
  if (timer) clearInterval(timer);
});
</script>

<template>
  <v-chart class="chart" :option="option" />
</template>

<style scoped lang="scss">
.chart {
  width: 100%;
  height: 100%;
}
</style>