<template>
  <div class="page-wrapper">
    <div class="page-head">
      <div class="page-head__text">
        <h2 class="page-title">实时监控</h2>
        <div class="page-subtitle">
          <span class="source-chip is-live">自动刷新 · 每 5 秒</span>
          <span>保留最近 20 条采样</span>
        </div>
      </div>
      <div class="page-head__actions">
        <el-button @click="refreshMetrics">
          <el-icon><Refresh /></el-icon>
          刷新
        </el-button>
      </div>
    </div>

    <div class="stat-grid">
      <div class="stat-tile" v-for="item in statItems" :key="item.key">
        <div class="stat-tile__icon" :class="item.tone">
          <el-icon><component :is="item.icon" /></el-icon>
        </div>
        <div class="stat-tile__body">
          <div class="stat-tile__value">{{ item.value }}</div>
          <div class="stat-tile__label">{{ item.label }}</div>
          <div class="stat-delta" :class="item.changeClass">{{ item.change }}</div>
        </div>
      </div>
    </div>

    <el-row :gutter="20" class="gap-card">
      <el-col :span="12">
        <div class="panel">
          <div class="panel__head"><span class="panel__title">请求流量趋势</span></div>
          <div class="panel__body">
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
          </div>
        </div>
      </el-col>
      <el-col :span="12">
        <div class="panel">
          <div class="panel__head"><span class="panel__title">拦截分布</span></div>
          <div class="panel__body">
            <div class="chart-box">
              <Doughnut :data="distChartData" :options="distChartOptions" />
            </div>
          </div>
        </div>
      </el-col>
    </el-row>

    <div class="panel gap-card">
      <div class="panel__head"><span class="panel__title">历史记录</span></div>
      <el-table :data="historyData" class="w-full" height="300">
        <el-table-column prop="timestamp" label="时间" width="180" />
        <el-table-column prop="total" label="总请求" />
        <el-table-column prop="blocked" label="拦截数" />
        <el-table-column prop="matched" label="规则命中" />
        <el-table-column prop="limited" label="限流数" />
        <template #empty>
          <div class="empty-state">
            <div class="empty-state__icon">📈</div>
            <div class="empty-state__title">暂无采样数据</div>
            <div class="empty-state__hint">监控数据每 5 秒采样一次，稍候即可看到</div>
          </div>
        </template>
      </el-table>
    </div>
  </div>
</template>

<script lang="ts" setup>
import { ref, onMounted, onUnmounted, computed, shallowRef } from 'vue'
import { Line, Doughnut } from 'vue-chartjs'
import {
  Refresh, DataLine, CircleCloseFilled, Files, Aim, Timer,
} from '@element-plus/icons-vue'
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
      icon: DataLine,
      tone: 'tone-brand',
      change: pct(metrics.requests_total, prev?.total ?? 0),
      changeClass: trend(metrics.requests_total, prev?.total ?? 0),
    },
    {
      key: 'blocked',
      label: '拦截数',
      value: metrics.blocked,
      icon: CircleCloseFilled,
      tone: 'tone-danger',
      change: pct(metrics.blocked, prev?.blocked ?? 0),
      changeClass: trend(metrics.blocked, prev?.blocked ?? 0),
    },
    {
      key: 'rules',
      label: '加载规则数',
      value: metrics.rules_loaded,
      icon: Files,
      tone: 'tone-info',
      change: pct(metrics.rules_loaded, prev?.rules_loaded ?? 0),
      changeClass: trend(metrics.rules_loaded, prev?.rules_loaded ?? 0),
    },
    {
      key: 'match',
      label: '规则命中',
      value: metrics.rule_matched,
      icon: Aim,
      tone: 'tone-warning',
      change: pct(metrics.rule_matched, prev?.matched ?? 0),
      changeClass: trend(metrics.rule_matched, prev?.matched ?? 0),
    },
    {
      key: 'limited',
      label: '限流数',
      value: metrics.rate_limited,
      icon: Timer,
      tone: 'tone-purple',
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
.stat-delta {
  margin-top: 4px;
  font-size: 12px;
  font-weight: 600;
  color: var(--text-disabled);
}

.stat-delta.increase {
  color: #ff6b6b;
}

.stat-delta.decrease {
  color: #67c23a;
}
</style>
