<template>
  <div class="page-wrapper">
    <div class="page-header">
      <h2 class="page-title">概览</h2>
      <span class="help-text">
        自动刷新: 每 {{ refreshInterval }} 秒
        <el-text type="info" size="small" style="margin-left: 8px">(更新于 {{ lastUpdated }})</el-text>
      </span>
    </div>

    <el-card class="stats-card" shadow="hover">
      <el-row :gutter="20">
        <el-col :span="6">
          <el-statistic :value="totalRequests" label="总请求数" />
        </el-col>
        <el-col :span="6">
          <el-statistic :value="blockedCount" label="拦截数" status="danger" />
        </el-col>
        <el-col :span="6">
          <el-statistic :value="ruleMatched" label="规则命中" />
        </el-col>
        <el-col :span="6">
          <el-statistic :value="rateLimited" label="限流数" status="warning" />
        </el-col>
      </el-row>
    </el-card>

    <el-row :gutter="20" class="gap-card">
      <el-col :span="12">
        <el-card shadow="hover">
          <template #header>
            <div class="card-title">请求趋势</div>
          </template>
          <div class="chart-box">
            <Line
              :data="{
                labels: trendLabels,
                datasets: [
                  {
                    label: '请求数',
                    data: trendRequestsData,
                    borderColor: '#409fff',
                    backgroundColor: 'rgba(64, 159, 255, 0.1)',
                    tension: 0.4,
                    fill: true,
                  },
                  {
                    label: '拦截数',
                    data: trendBlockedData,
                    borderColor: '#ff4d4f',
                    backgroundColor: 'rgba(255, 77, 79, 0.1)',
                    tension: 0.4,
                    fill: true,
                  },
                ],
              }"
              :options="trendChartOptions"
            />
          </div>
        </el-card>
      </el-col>
      <el-col :span="12">
        <el-card shadow="hover">
          <template #header>
            <div class="card-title">拦截原因分布</div>
          </template>
          <div class="chart-box">
            <Pie :data="reasonChartData" :options="reasonChartOptions" />
          </div>
        </el-card>
      </el-col>
    </el-row>

    <el-row :gutter="20" class="gap-card">
      <el-col :span="12">
        <el-card shadow="hover">
          <template #header>
            <div class="card-title">规则加载状态</div>
          </template>
          <el-row :gutter="10">
            <el-col :span="12">
              <el-tag type="success" style="margin-right: 10px">
                总规则数: {{ totalRules }}
              </el-tag>
            </el-col>
            <el-col :span="12">
              <el-tag :type="currentMode === 'block' ? 'danger' : 'warning'">
                {{ currentMode === 'block' ? '拦截模式' : '检测模式' }}
              </el-tag>
            </el-col>
          </el-row>
        </el-card>
      </el-col>
      <el-col :span="12">
        <el-card shadow="hover">
          <template #header>
            <div class="card-title">IP 列表状态</div>
          </template>
          <el-row :gutter="10">
            <el-col :span="12">
              <el-statistic :value="allowCount" label="白名单 IP 数" />
            </el-col>
            <el-col :span="12">
              <el-statistic :value="denyCount" label="黑名单 IP 数" status="danger" />
            </el-col>
          </el-row>
        </el-card>
      </el-col>
    </el-row>
  </div>
</template>

<script lang="ts" setup>
import { ref, onMounted, onUnmounted, watch, computed, shallowRef } from 'vue'
import { Line, Pie } from 'vue-chartjs'
import { useWafStore } from '@/stores/waf'

const wafStore = useWafStore()

const refreshInterval = 5
const lastUpdated = ref('')

// Stats are derived directly from the store — no manual sync/watch needed.
const totalRequests = computed(() => wafStore.metrics.requests_total)
const blockedCount = computed(() => wafStore.metrics.blocked)
const ruleMatched = computed(() => wafStore.metrics.rule_matched)
const rateLimited = computed(() => wafStore.metrics.rate_limited)
const totalRules = computed(() => wafStore.rules.length)
const currentMode = computed(() => wafStore.config.mode)
const allowCount = computed(() => wafStore.config.allow.length)
const denyCount = computed(() => wafStore.config.deny.length)

// Trend data (capped at 20 points).
const trendData = ref<
  { timestamp: number; requests: number; blocked: number }[]
>([])

// shallowRef avoids re-rendering chart data through Vue's deep reactivity.
const trendLabels = shallowRef<string[]>([])
const trendRequestsData = shallowRef<number[]>([])
const trendBlockedData = shallowRef<number[]>([])

const trendChartOptions = ref({
  responsive: true,
  maintainAspectRatio: false,
  scales: {
    y: { beginAtZero: true },
  },
  animation: false,
  plugins: { legend: { position: 'top' } },
})

const reasonChartOptions = ref({
  responsive: true,
  maintainAspectRatio: false,
  animation: false,
  plugins: { legend: { position: 'right' } },
})

// Pie data: rule match, rate limit, other-blocked, and normal requests.
const reasonChartData = computed(() => {
  const m = wafStore.metrics
  const blocked = m.blocked
  const otherBlocked = Math.max(0, blocked - m.rule_matched - m.rate_limited)
  const normal = Math.max(0, m.requests_total - blocked)
  return {
    labels: ['规则命中', '限流', '其它拦截', '正常'],
    datasets: [
      {
        data: [m.rule_matched, m.rate_limited, otherBlocked, normal],
        backgroundColor: ['#409ef4', '#e6a23c', '#ff4d4f', '#67c23a'],
      },
    ],
  }
})

const updateTrend = () => {
  const now = Date.now()
  trendData.value.push({
    timestamp: now,
    requests: wafStore.metrics.requests_total,
    blocked: wafStore.metrics.blocked,
  })
  if (trendData.value.length > 20) {
    trendData.value = trendData.value.slice(-20)
  }
  const data = trendData.value
  trendLabels.value = data.map((d) => new Date(d.timestamp).toLocaleTimeString())
  trendRequestsData.value = data.map((d) => d.requests)
  trendBlockedData.value = data.map((d) => d.blocked)
  lastUpdated.value = new Date(now).toLocaleTimeString()
}

const loadInitialData = async () => {
  await Promise.all([
    wafStore.loadMetrics(),
    wafStore.loadRules(),
    wafStore.loadConfig(),
    wafStore.loadAllowList(),
    wafStore.loadDenyList(),
  ])
  // The initial trend point is pushed by the metrics watcher below.
}

// Single source of truth: whenever the metrics object changes (from a load),
// update the trend + last-updated timestamp. This replaces the previous
// double-update from running updateCharts both in the interval and the watch.
watch(
  () => wafStore.metrics,
  () => updateTrend(),
  { deep: true },
)

onMounted(() => {
  loadInitialData()

  const interval = setInterval(async () => {
    try {
      await wafStore.loadMetrics()
    } catch (error) {
      console.error('Failed to refresh metrics:', error)
    }
  }, refreshInterval * 1000)

  onUnmounted(() => clearInterval(interval))
})
</script>
