<template>
  <div class="page-wrapper">
    <div class="page-head">
      <div class="page-head__text">
        <h2 class="page-title">概览</h2>
        <div class="page-subtitle">
          <span class="source-chip">自动刷新 · 每 {{ refreshInterval }} 秒</span>
          <span>更新于 {{ lastUpdated || '—' }}</span>
        </div>
      </div>
      <div class="page-head__actions">
        <el-tag :type="currentMode === 'block' ? 'danger' : 'warning'" effect="light">
          {{ currentMode === 'block' ? '拦截模式' : '检测模式' }}
        </el-tag>
      </div>
    </div>

    <div class="stat-grid">
      <div class="stat-tile">
        <div class="stat-tile__icon tone-brand"><el-icon><DataLine /></el-icon></div>
        <div class="stat-tile__body">
          <div class="stat-tile__value">{{ totalRequests }}</div>
          <div class="stat-tile__label">总请求数</div>
        </div>
      </div>
      <div class="stat-tile">
        <div class="stat-tile__icon tone-danger"><el-icon><CircleCloseFilled /></el-icon></div>
        <div class="stat-tile__body">
          <div class="stat-tile__value">{{ blockedCount }}</div>
          <div class="stat-tile__label">拦截数</div>
        </div>
      </div>
      <div class="stat-tile">
        <div class="stat-tile__icon tone-warning"><el-icon><Aim /></el-icon></div>
        <div class="stat-tile__body">
          <div class="stat-tile__value">{{ ruleMatched }}</div>
          <div class="stat-tile__label">规则命中</div>
        </div>
      </div>
      <div class="stat-tile">
        <div class="stat-tile__icon tone-purple"><el-icon><Timer /></el-icon></div>
        <div class="stat-tile__body">
          <div class="stat-tile__value">{{ rateLimited }}</div>
          <div class="stat-tile__label">限流数</div>
        </div>
      </div>
    </div>

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
        <div class="panel">
          <div class="panel__head"><span class="panel__title">规则加载状态</span></div>
          <div class="panel__body">
            <div class="kv-list">
              <div class="kv-list__row">
                <span class="kv-list__k">已加载规则</span>
                <span class="kv-list__v">{{ totalRules }} 条</span>
              </div>
              <div class="kv-list__row">
                <span class="kv-list__k">运行模式</span>
                <el-tag :type="currentMode === 'block' ? 'danger' : 'warning'" effect="light">
                  {{ currentMode === 'block' ? '拦截模式' : '检测模式' }}
                </el-tag>
              </div>
            </div>
          </div>
        </div>
      </el-col>
      <el-col :span="12">
        <div class="panel">
          <div class="panel__head"><span class="panel__title">IP 列表状态</span></div>
          <div class="panel__body">
            <div class="kv-list">
              <div class="kv-list__row">
                <span class="kv-list__k">白名单</span>
                <span class="kv-list__v">{{ allowCount }} 个</span>
              </div>
              <div class="kv-list__row">
                <span class="kv-list__k">黑名单</span>
                <span class="kv-list__v kv-list__v--danger">{{ denyCount }} 个</span>
              </div>
            </div>
          </div>
        </div>
      </el-col>
    </el-row>
  </div>
</template>

<script lang="ts" setup>
import { ref, onMounted, onUnmounted, watch, computed, shallowRef } from 'vue'
import { Line, Pie } from 'vue-chartjs'
import { DataLine, CircleCloseFilled, Aim, Timer } from '@element-plus/icons-vue'
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
