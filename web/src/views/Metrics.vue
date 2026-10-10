<template>
  <div class="page-wrapper">
    <div class="page-header">
      <h2 class="page-title">实时监控</h2>
      <el-button @click="refreshMetrics">刷新</el-button>
    </div>

    <el-row :gutter="20">
      <el-col :span="8" v-for="item in statItems" :key="item.key">
        <el-card shadow="hover">
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

    <el-row :gutter="20" class="gap-card">
      <el-col :span="12">
        <el-card shadow="hover">
          <template #header>
            <div class="card-title">请求流量趋势</div>
          </template>
          <div class="chart-box">
            <Line
              :data="{
                labels: chartLabels,
                datasets: [
                  {
                    label: '请求数',
                    data: requestsData,
                    borderColor: '#409fff',
                    backgroundColor: 'rgba(64, 159, 255, 0.1)',
                    fill: true,
                    tension: 0.4,
                  },
                  {
                    label: '拦截数',
                    data: blockedData,
                    borderColor: '#ff4d4f',
                    backgroundColor: 'rgba(255, 77, 79, 0.1)',
                    fill: true,
                    tension: 0.4,
                  },
                ],
              }"
              :options="chartOptions"
            />
          </div>
        </el-card>
      </el-col>
      <el-col :span="12">
        <el-card shadow="hover">
          <template #header>
            <div class="card-title">拦截分布</div>
          </template>
          <div class="chart-box">
            <Doughnut :data="distChartData" :options="distChartOptions" />
          </div>
        </el-card>
      </el-col>
    </el-row>

    <el-row :gutter="20" class="gap-card">
      <el-col :span="24">
        <el-card shadow="hover">
          <template #header>
            <div class="card-title">历史记录</div>
          </template>
          <el-table :data="historyData" class="w-full" height="300">
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

  const pct = (cur: number, base: number) =>
    prev && base > 0 ? (((cur - base) * 100) / base).toFixed(1) + '%' : '-'
  const trend = (cur: number, base: number) =>
    prev && cur > base ? 'increase' : cur < base ? 'decrease' : ''

  return [
    {
      key: 'total',
      label: '总请求数',
      value: metrics.requests_total,
      change: pct(metrics.requests_total, prev?.total ?? 0),
      changeClass: trend(metrics.requests_total, prev?.total ?? 0),
    },
    {
      key: 'blocked',
      label: '拦截数',
      value: metrics.blocked,
      change: pct(metrics.blocked, prev?.blocked ?? 0),
      changeClass: trend(metrics.blocked, prev?.blocked ?? 0),
    },
    {
      key: 'rules',
      label: '加载规则数',
      value: metrics.rules_loaded,
      change: pct(metrics.rules_loaded, prev?.rules_loaded ?? 0),
      changeClass: trend(metrics.rules_loaded, prev?.rules_loaded ?? 0),
    },
    {
      key: 'match',
      label: '规则命中',
      value: metrics.rule_matched,
      change: pct(metrics.rule_matched, prev?.matched ?? 0),
      changeClass: trend(metrics.rule_matched, prev?.matched ?? 0),
    },
    {
      key: 'limited',
      label: '限流数',
      value: metrics.rate_limited,
      change: pct(metrics.rate_limited, prev?.limited ?? 0),
      changeClass: trend(metrics.rate_limited, prev?.limited ?? 0),
    },
  ]
})

const historyData = ref<
  Array<{
    timestamp: string
    total: number
    blocked: number
    matched: number
    limited: number
  }>
>([])

// shallowRef avoids chart data passing through Vue's deep reactivity.
const chartLabels = shallowRef<string[]>([])
const requestsData = shallowRef<number[]>([])
const blockedData = shallowRef<number[]>([])
const distLabels = shallowRef<string[]>(['规则命中', '限流', '正常请求'])

const chartOptions = ref({
  responsive: true,
  maintainAspectRatio: false,
  scales: { y: { beginAtZero: true } },
  animation: false,
})

const distChartOptions = ref({
  responsive: true,
  maintainAspectRatio: false,
  animation: false,
  plugins: { legend: { position: 'right' } },
})

// Pie distribution: rule match, rate limit, and genuinely normal requests.
const distChartData = computed(() => {
  const m = wafStore.metrics
  const normal = Math.max(0, m.requests_total - m.blocked)
  return {
    labels: distLabels.value,
    datasets: [
      {
        data: [m.rule_matched, m.rate_limited, normal],
        backgroundColor: ['#409ef4', '#e6a23c', '#67c23a'],
      },
    ],
  }
})

const savePrev = () => {
  const m = wafStore.metrics
  previousMetrics.value = {
    total: m.requests_total,
    blocked: m.blocked,
    matched: m.rule_matched,
    limited: m.rate_limited,
    rules_loaded: m.rules_loaded,
  }
}

const recordHistory = () => {
  const now = new Date()
  const timestamp = now.toLocaleTimeString()
  historyData.value.unshift({
    timestamp,
    total: wafStore.metrics.requests_total,
    blocked: wafStore.metrics.blocked,
    matched: wafStore.metrics.rule_matched,
    limited: wafStore.metrics.rate_limited,
  })
  if (historyData.value.length > 20) {
    historyData.value = historyData.value.slice(0, 20)
  }

  chartLabels.value = [timestamp, ...chartLabels.value.slice(0, 19)]
  requestsData.value = [wafStore.metrics.requests_total, ...requestsData.value.slice(0, 19)]
  blockedData.value = [wafStore.metrics.blocked, ...blockedData.value.slice(0, 19)]
}

const refreshMetrics = async () => {
  await wafStore.loadMetrics()
  savePrev()
  recordHistory()
}

onMounted(() => {
  const init = async () => {
    await wafStore.loadMetrics()
    savePrev()
    recordHistory()
  }
  init()

  const interval = setInterval(async () => {
    try {
      await wafStore.loadMetrics()
      savePrev()
      recordHistory()
    } catch (error) {
      console.error('Failed to refresh metrics:', error)
    }
  }, 5000)

  onUnmounted(() => clearInterval(interval))
})
</script>

<style scoped>
.stat-item {
  text-align: center;
  padding: 16px 0;
}

.stat-value {
  font-size: 28px;
  font-weight: 600;
  color: var(--text-primary);
  margin-bottom: 8px;
}

.stat-label {
  font-size: 14px;
  color: var(--text-disabled);
  margin-bottom: 6px;
}

.stat-change {
  font-size: 12px;
  font-weight: 600;
}

.stat-change.increase {
  color: #ff6b6b;
}

.stat-change.decrease {
  color: #67c23a;
}
</style>
