<template>
  <div class="metrics-page">
    <div class="page-header">
      <h2 class="page-title">实时监控</h2>
      <el-button @click="refreshMetrics">刷新</el-button>
    </div>

    <el-row :gutter="20">
      <el-col :span="8" v-for="item in statItems" :key="item.key">
        <el-card>
          <div class="stat-item">
            <div class="stat-value">{{ item.value }}</div>
            <div class="stat-label">{{ item.label }}</div>
            <div class="stat-change" :class="item.changeClass">
              {{ item.change }}
            </div>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <el-row :gutter="20" style="margin-top: 20px">
      <el-col :span="12">
        <el-card>
          <template #header>
            <div class="card-title">请求流量趋势</div>
          </template>
          <div style="height: 300px">
            <Line :data="{ labels: chartLabels, datasets: [{ label: '请求数', data: requestsData, borderColor: '#409fff', backgroundColor: 'rgba(64, 159, 255, 0.1)', fill: true, tension: 0.4 }, { label: '拦截数', data: blockedData, borderColor: '#ff4d4f', backgroundColor: 'rgba(255, 77, 79, 0.1)', fill: true, tension: 0.4 }] }" :options="chartOptions" />
          </div>
        </el-card>
      </el-col>
      <el-col :span="12">
        <el-card>
          <template #header>
            <div class="card-title">拦截分布</div>
          </template>
          <div style="height: 300px">
            <Doughnut :data="{ labels: distLabels, datasets: [{ data: distData, backgroundColor: ['#409fff', '#ffa500', '#67c23a'] }] }" :options="distChartOptions" />
          </div>
        </el-card>
      </el-col>
    </el-row>

    <el-row :gutter="20" style="margin-top: 20px">
      <el-col :span="24">
        <el-card>
          <template #header>
            <div class="card-title">历史记录</div>
          </template>
          <el-table :data="historyData" style="width: 100%" height="300">
            <el-table-column prop="timestamp" label="时间" width="180" />
            <el-table-column prop="total" label="总请求" />
            <el-table-column prop="blocked" label="拦截数" />
            <el-table-column prop="matched" label="规则命中" />
            <el-table-column prop="limited" label="限流数" />
          </el-table>
        </el-card>
      </el-col>
    </el-row>
  </div>
</template>

<script lang="ts" setup>
import { ref, onMounted, onUnmounted, computed, shallowRef } from 'vue'
import { Line, Doughnut } from 'vue-chartjs'
import { useWafStore } from '@/stores/waf'

const wafStore = useWafStore()

const previousMetrics = ref<{
  total: number
  blocked: number
  matched: number
  limited: number
  rules_loaded: number
} | null>(null)

const statItems = computed(() => {
  const metrics = wafStore.metrics
  const prev = previousMetrics.value

  return [
    {
      key: 'total',
      label: '总请求数',
      value: metrics.requests_total,
      change: prev && prev.total > 0 ? ((metrics.requests_total - prev.total) * 100 / prev.total).toFixed(1) + '%' : '-',
      changeClass: prev && metrics.requests_total > prev.total ? 'increase' : '',
    },
    {
      key: 'blocked',
      label: '拦截数',
      value: metrics.blocked,
      change: prev && prev.blocked > 0 ? ((metrics.blocked - prev.blocked) * 100 / prev.blocked).toFixed(1) + '%' : '-',
      changeClass: prev && metrics.blocked > prev.blocked ? 'increase' : '',
    },
    {
      key: 'rules',
      label: '加载规则数',
      value: metrics.rules_loaded,
      change: prev && prev.rules_loaded > 0 ? ((metrics.rules_loaded - prev.rules_loaded) * 100 / prev.rules_loaded).toFixed(1) + '%' : '-',
      changeClass: '',
    },
    {
      key: 'match',
      label: '规则命中',
      value: metrics.rule_matched,
      change: prev && prev.matched > 0 ? ((metrics.rule_matched - prev.matched) * 100 / prev.matched).toFixed(1) + '%' : '-',
      changeClass: prev && metrics.rule_matched > prev.matched ? 'increase' : '',
    },
    {
      key: 'limited',
      label: '限流数',
      value: metrics.rate_limited,
      change: prev && prev.limited > 0 ? ((metrics.rate_limited - prev.limited) * 100 / prev.limited).toFixed(1) + '%' : '-',
      changeClass: prev && metrics.rate_limited > prev.limited ? 'increase' : '',
    },
  ]
})

const historyData = ref<Array<{
  timestamp: string
  total: number
  blocked: number
  matched: number
  limited: number
}>>([])

// 使用 shallowRef 避免图表数据的深度响应式导致的性能问题和潜在的栈溢出
const chartLabels = shallowRef<string[]>([])
const requestsData = shallowRef<number[]>([])
const blockedData = shallowRef<number[]>([])
const distLabels = shallowRef<string[]>(['规则命中', '限流', '正常请求'])
const distData = shallowRef<number[]>([0, 0, 0])

const chartOptions = ref({
  responsive: true,
  maintainAspectRatio: false,
  scales: {
    y: {
      beginAtZero: true,
    },
  },
  animation: false, // 禁用动画提升性能
})

const distChartOptions = ref({
  responsive: true,
  maintainAspectRatio: false,
  animation: false,
})

const refreshMetrics = async () => {
  await wafStore.loadMetrics()
}

const updateCharts = () => {
  const now = new Date()
  const timestamp = now.toLocaleTimeString()

  historyData.value.unshift({
    timestamp,
    total: wafStore.metrics.requests_total,
    blocked: wafStore.metrics.blocked,
    matched: wafStore.metrics.rule_matched,
    limited: wafStore.metrics.rate_limited,
  })

  // Keep last 20 records
  if (historyData.value.length > 20) {
    historyData.value = historyData.value.slice(0, 20)
  }

  // 更新响应式数据（创建新数组触发浅层响应）
  chartLabels.value = [timestamp, ...chartLabels.value.slice(0, 19)]
  requestsData.value = [wafStore.metrics.requests_total, ...requestsData.value.slice(0, 19)]
  blockedData.value = [wafStore.metrics.blocked, ...blockedData.value.slice(0, 19)]

  // 更新分布图数据
  const normalRequests = Math.max(0, wafStore.metrics.requests_total - wafStore.metrics.blocked - wafStore.metrics.rule_matched - wafStore.metrics.rate_limited)
  distData.value = [
    wafStore.metrics.rule_matched,
    wafStore.metrics.rate_limited,
    normalRequests,
  ]
}

onMounted(() => {
  // 初始加载
  const init = async () => {
    await wafStore.loadMetrics()

    // Set initial values
    previousMetrics.value = {
      total: wafStore.metrics.requests_total,
      blocked: wafStore.metrics.blocked,
      matched: wafStore.metrics.rule_matched,
      limited: wafStore.metrics.rate_limited,
      rules_loaded: wafStore.metrics.rules_loaded,
    }

    updateCharts()
  }
  init()

  // Auto refresh every 5 seconds
  const interval = setInterval(async () => {
    try {
      await wafStore.loadMetrics()
      
      // 更新 previousMetrics 为加载前的值（用于计算变化率）
      // 注意：这里应该在 loadMetrics 之前保存，但为了简化逻辑，我们在加载后更新
      // 实际的变化率计算使用的是上一轮保存的 previousMetrics
      previousMetrics.value = {
        total: wafStore.metrics.requests_total,
        blocked: wafStore.metrics.blocked,
        matched: wafStore.metrics.rule_matched,
        limited: wafStore.metrics.rate_limited,
        rules_loaded: wafStore.metrics.rules_loaded,
      }
      
      updateCharts()
    } catch (error) {
      console.error('Failed to refresh metrics:', error)
    }
  }, 5000)

  onUnmounted(() => {
    clearInterval(interval)
  })
})
</script>

<style scoped>
.metrics-page {
  padding: 20px;
}

.page-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 20px;
}

.page-title {
  margin: 0;
  color: #303133;
}

.stat-item {
  text-align: center;
  padding: 20px;
}

.stat-value {
  font-size: 28px;
  font-weight: 600;
  color: #303133;
  margin-bottom: 10px;
}

.stat-label {
  font-size: 14px;
  color: #909399;
  margin-bottom: 8px;
}

.stat-change {
  font-size: 12px;
}

.stat-change.increase {
  color: #f56c6c;
}

.stat-change.decrease {
  color: #67c23a;
}

.card-title {
  font-weight: 600;
  color: #303133;
}
</style>