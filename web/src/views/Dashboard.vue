<template>
  <div class="dashboard">
    <el-card class="stats-card" style="margin-bottom: 20px">
      <div class="stats-title">概览</div>
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

    <el-row :gutter="20">
      <el-col :span="12">
        <el-card>
          <template #header>
            <div class="card-title">请求趋势</div>
          </template>
          <div style="height: 300px">
            <Line :data="{ labels: trendLabels, datasets: [{ label: '请求数', data: trendRequestsData, borderColor: '#409fff', backgroundColor: 'rgba(64, 159, 255, 0.1)', tension: 0.4 }, { label: '拦截数', data: trendBlockedData, borderColor: '#ff4d4f', backgroundColor: 'rgba(255, 77, 79, 0.1)', tension: 0.4 }] }" :options="trendChartOptions" ref="trendChart" />
          </div>
        </el-card>
      </el-col>
      <el-col :span="12">
        <el-card>
          <template #header>
            <div class="card-title">拦截原因分布</div>
          </template>
          <div style="height: 300px">
            <Pie :data="{ labels: reasonLabels, datasets: [{ data: reasonData, backgroundColor: ['#409fff', '#ffa500', '#67c23a', '#dfdfdf'] }] }" :options="reasonChartOptions" ref="reasonChart" />
          </div>
        </el-card>
      </el-col>
    </el-row>

    <el-row :gutter="20" style="margin-top: 20px">
      <el-col :span="12">
        <el-card>
          <template #header>
            <div class="card-title">规则加载状态</div>
          </template>
          <div>
            <el-tag type="success" style="margin-right: 10px">总规则数: {{ totalRules }}</el-tag>
            <el-tag type="info" style="margin-right: 10px">模式: {{ currentMode === 'block' ? '拦截模式' : '检测模式' }}</el-tag>
          </div>
        </el-card>
      </el-col>
      <el-col :span="12">
        <el-card>
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
import { ref, onMounted, onUnmounted, watch, shallowRef } from 'vue'
import { Line, Pie } from 'vue-chartjs'
import { useWafStore } from '@/stores/waf'

const wafStore = useWafStore()

const totalRequests = ref(0)
const blockedCount = ref(0)
const ruleMatched = ref(0)
const rateLimited = ref(0)
const totalRules = ref(0)
const currentMode = ref('block')
const allowCount = ref(0)
const denyCount = ref(0)

let trendData: { timestamp: number; requests: number; blocked: number }[] = []

// 使用 shallowRef 避免图表数据的深度响应式导致的性能问题和潜在的栈溢出
const trendLabels = shallowRef<string[]>([])
const trendRequestsData = shallowRef<number[]>([])
const trendBlockedData = shallowRef<number[]>([])
const reasonLabels = shallowRef<string[]>(['规则命中', '限流', '白名单', '其它'])
const reasonData = shallowRef<number[]>([0, 0, 0, 0])

const trendChartOptions = ref({
  responsive: true,
  maintainAspectRatio: false,
  scales: {
    y: {
      beginAtZero: true,
    },
  },
  animation: false,
})

const reasonChartOptions = ref({
  responsive: true,
  maintainAspectRatio: false,
  animation: false,
})

const updateCharts = () => {
  const now = Date.now()
  trendData.push({
    timestamp: now,
    requests: wafStore.metrics.requests_total,
    blocked: wafStore.metrics.blocked,
  })

  // Keep last 20 data points
  if (trendData.length > 20) {
    trendData = trendData.slice(-20)
  }

  // 更新响应式数据（创建新数组触发浅层响应）
  trendLabels.value = trendData.map((d) => new Date(d.timestamp).toLocaleTimeString())
  trendRequestsData.value = trendData.map((d) => d.requests)
  trendBlockedData.value = trendData.map((d) => d.blocked)

  // 更新拦截原因分布数据
  const normalRequests = Math.max(0, wafStore.metrics.requests_total - wafStore.metrics.blocked - wafStore.metrics.rule_matched - wafStore.metrics.rate_limited)
  reasonData.value = [
    wafStore.metrics.rule_matched,
    wafStore.metrics.rate_limited,
    wafStore.config.allow.length > 0 ? 0 : normalRequests, // 简化：白名单计数暂时设为0
    normalRequests,
  ]
}

const loadInitialData = async () => {
  await Promise.all([
    wafStore.loadMetrics(),
    wafStore.loadRules(),
    wafStore.loadConfig(),
    wafStore.loadAllowList(),
    wafStore.loadDenyList(),
  ])

  // Update stats
  totalRequests.value = wafStore.metrics.requests_total
  blockedCount.value = wafStore.metrics.blocked
  ruleMatched.value = wafStore.metrics.rule_matched
  rateLimited.value = wafStore.metrics.rate_limited
  totalRules.value = wafStore.rules.length
  currentMode.value = wafStore.config.mode
  allowCount.value = wafStore.config.allow.length
  denyCount.value = wafStore.config.deny.length

  // Initial chart update
  updateCharts()
}

onMounted(() => {
  loadInitialData()

  // Set up interval for auto-refresh
  const interval = setInterval(async () => {
    try {
      await wafStore.loadMetrics()
      updateCharts()
    } catch (error) {
      console.error('Failed to refresh metrics:', error)
    }
  }, 5000)

  onUnmounted(() => {
    clearInterval(interval)
  })
})

// 使用 watch 深度监听 metrics 变化，同步更新统计卡片
watch(
  () => wafStore.metrics,
  (newMetrics) => {
    totalRequests.value = newMetrics.requests_total
    blockedCount.value = newMetrics.blocked
    ruleMatched.value = newMetrics.rule_matched
    rateLimited.value = newMetrics.rate_limited
    updateCharts()
  },
  { deep: true },
)

watch(
  () => wafStore.rules,
  (newRules) => {
    totalRules.value = newRules.length
  },
  { deep: true },
)

watch(
  () => wafStore.config,
  (newConfig) => {
    currentMode.value = newConfig.mode
    allowCount.value = newConfig.allow.length
    denyCount.value = newConfig.deny.length
  },
  { deep: true },
)
</script>

<style scoped>
.dashboard {
  padding: 20px;
}

.stats-card {
  border-radius: 8px;
  box-shadow: 0 2px 12px 0 rgba(0, 0, 0, 0.1);
}

.stats-title {
  font-size: 16px;
  color: #606266;
  margin-bottom: 15px;
}

.card-title {
  font-weight: 600;
  color: #303133;
}

.el-statistic {
  font-size: 14px;
}
</style>