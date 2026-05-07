<script setup lang="ts">
import { ref, onMounted, onBeforeUnmount } from "vue";
import { graphic } from "echarts/core";
import { ElMessage } from "element-plus";
import axios from 'axios';

const INDEXER_AUTH = btoa('admin:It2bqmagNT.hxelVM9BrhnKwAZ?5Iz6S');
const option = ref({});

const getData = async () => {
  try {
    // 1. 获取今日零点时间
    const todayStart = new Date();
    todayStart.setHours(0, 0, 0, 0);
    const startTime = todayStart.toISOString();

    // 2. 从 Indexer 获取今日告警趋势
    const res = await axios.post('/wazuh-indexer/wazuh-alerts-*/_search', {
      size: 0,
      query: {
        range: { timestamp: { gte: startTime, lte: "now" } }
      },
      aggs: {
        alerts_per_hour: {
          date_histogram: {
            field: "timestamp",
            fixed_interval: "1h",
            extended_bounds: { min: startTime, max: "now" }
          },
          aggs: {
            levels: {
              range: {
                field: "rule.level",
                ranges: [
                  { from: 3, to: 8, key: "low" },
                  { from: 8, to: 12, key: "mid" },
                  { from: 12, key: "high" }
                ]
              }
            }
          }
        }
      }
    }, {
      headers: { 'Authorization': `Basic ${INDEXER_AUTH}` }
    });

    const buckets = res.data.aggregations.alerts_per_hour.buckets;
    
    // 3. 准备 X 轴和三条曲线的数据
    const xData = buckets.map((b: any) => new Date(b.key).getHours() + ":00");
    const yDataLow = buckets.map((b: any) => b.levels.buckets.find((l: any) => l.key === 'low').doc_count);
    const yDataMid = buckets.map((b: any) => b.levels.buckets.find((l: any) => l.key === 'mid').doc_count);
    const yDataHigh = buckets.map((b: any) => b.levels.buckets.find((l: any) => l.key === 'high').doc_count);

    setOption(xData, yDataLow, yDataMid, yDataHigh);
  } catch (err: any) {
    console.error("趋势图数据同步失败:", err);
  }
};

const setOption = (xData: any[], yLow: any[], yMid: any[], yHigh: any[]) => {
  // 保持你源码中的所有配置，仅在 series 中增加/修改对应数据
  option.value = {
    xAxis: {
      type: "category",
      data: xData,
      boundaryGap: false,
      splitLine: { show: true, lineStyle: { color: "rgba(31,99,163,.2)" } },
      axisLine: { lineStyle: { color: "rgba(31,99,163,.1)" } },
      axisLabel: { color: "#7EB7FD", fontWeight: "500" },
    },
    yAxis: {
      type: "value",
      splitLine: { show: true, lineStyle: { color: "rgba(31,99,163,.2)" } },
      axisLine: { lineStyle: { color: "rgba(31,99,163,.1)" } },
      axisLabel: { color: "#7EB7FD", fontWeight: "500" },
    },
    tooltip: {
      trigger: "axis",
      backgroundColor: "rgba(0,0,0,.6)",
      borderColor: "rgba(147, 235, 248, .8)",
      textStyle: { color: "#FFF" },
    },
    grid: {
      show: true, left: "10px", right: "30px", bottom: "10px", top: "32px", containLabel: true, borderColor: "#1F63A3",
    },
    series: [
      {
        data: yLow,
        type: "line",
        smooth: true,
        symbol: "none",
        name: "低危告警",
        color: "rgba(11,252,127,.7)", // 调整为绿色系
        areaStyle: {
          color: new graphic.LinearGradient(0, 0, 0, 1, [
            { offset: 0, color: "rgba(11,252,127,.7)" },
            { offset: 1, color: "rgba(11,252,127,.0)" },
          ]),
        },
      },
      {
        data: yMid,
        type: "line",
        smooth: true,
        symbol: "none",
        name: "中危告警",
        color: "rgba(252,144,16,.7)", // 原有的橙色
        areaStyle: {
          color: new graphic.LinearGradient(0, 0, 0, 1, [
            { offset: 0, color: "rgba(252,144,16,.7)" },
            { offset: 1, color: "rgba(252,144,16,.0)" },
          ]),
        },
      },
      {
        data: yHigh,
        type: "line",
        smooth: true,
        symbol: "none",
        name: "高危告警",
        color: "rgba(244,2,60,.7)", // 红色
        areaStyle: {
          color: new graphic.LinearGradient(0, 0, 0, 1, [
            { offset: 0, color: "rgba(244,2,60,.7)" },
            { offset: 1, color: "rgba(244,2,60,.0)" },
          ]),
        },
        // 保留你喜欢的高值气泡标注
        markPoint: {
          data: [
            { name: "峰值", type: "max", valueDim: "y", symbol: "rect", symbolSize: [60, 26], symbolOffset: [0, -20],
              itemStyle: { color: "rgba(0,0,0,0)" },
              label: { color: "#F4023C", backgroundColor: "rgba(244,2,60,0.1)", borderRadius: 6, padding: [7, 14], borderWidth: 0.5, borderColor: "rgba(244,2,60,.5)", formatter: "最高风险: {c}" }
            }
          ]
        }
      },
    ],
  };
};

let timer: any = null;
onMounted(() => {
  getData();
  timer = setInterval(getData, 60000);
});
onBeforeUnmount(() => clearInterval(timer));
</script>

<template>
  <v-chart class="chart" :option="option" v-if="JSON.stringify(option) != '{}'" />
</template>