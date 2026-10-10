<template>
  <div class="audit-page">
    <el-alert
      v-if="!bastionStore.bastionEnabled"
      :title="bastionStore.bastionError || 'SSH bastion is not enabled'"
      type="warning"
      style="margin-bottom: 20px;"
    />
    <div class="page-header">
      <h2 class="page-title">命令审计</h2>
      <div class="filter-controls">
        <el-input
          v-model="filterUser"
          placeholder="过滤用户名"
          style="width: 160px"
          @input="applyFilters"
        />
        <el-input
          v-model="filterSession"
          placeholder="过滤会话 ID"
          style="width: 160px"
          @input="applyFilters"
        />
        <el-button type="primary" @click="loadData">
          <RefreshRight />
          刷新
        </el-button>
      </div>
    </div>

    <el-card>
      <el-table :data="filteredEvents" style="width: 100%" v-loading="bastionStore.loading">
        <el-table-column prop="timestamp" label="时间" width="160">
          <template #default="scope">
            {{ formatTime(scope.row.timestamp) }}
          </template>
        </el-table-column>
        <el-table-column prop="username" label="用户" width="120" />
        <el-table-column prop="session_id" label="会话 ID" width="160" />
        <el-table-column prop="command" label="命令" />
        <el-table-column prop="action" label="操作" width="100">
          <template #default="scope">
            <el-tag :type="scope.row.blocked ? 'danger' : 'info'">
              {{ scope.row.blocked ? '阻止' : scope.row.action }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="client_ip" label="客户端 IP" width="140" />
        <el-table-column prop="rule_id" label="规则 ID" width="120" />
      </el-table>
    </el-card>

    <!-- Filters -->
    <el-card style="margin-top: 20px;">
      <div slot="header">
        <span>统计</span>
      </div>
      <el-row :gutter="20">
        <el-col :span="6">
          <div class="stat-box">
            <div class="stat-value">{{ totalCount }}</div>
            <div class="stat-label">总事件数</div>
          </div>
        </el-col>
        <el-col :span="6">
          <div class="stat-box">
            <div class="stat-value stat-danger">{{ blockedCount }}</div>
            <div class="stat-label">阻止命令</div>
          </div>
        </el-col>
        <el-col :span="6">
          <div class="stat-box">
            <div class="stat-value stat-primary">{{ commandCount }}</div>
            <div class="stat-label">执行命令</div>
          </div>
        </el-col>
        <el-col :span="6">
          <div class="stat-box">
            <div class="stat-value">{{ uniqueUsers }}</div>
            <div class="stat-label">活跃用户</div>
          </div>
        </el-col>
      </el-row>
    </el-card>
  </div>
</template>

<script lang="ts" setup>
import { ref, computed, onMounted } from 'vue'
import { RefreshRight } from '@element-plus/icons-vue'
import { useBastionStore } from '@/stores/bastion'

const bastionStore = useBastionStore()
const filterUser = ref('')
const filterSession = ref('')

const filteredEvents = computed(() => {
  return bastionStore.auditEvents.filter(e => {
    if (filterUser.value && e.username !== filterUser.value) {
      return false
    }
    if (filterSession.value && !e.session_id?.includes(filterSession.value)) {
      return false
    }
    return true
  })
})

const totalCount = computed(() => filteredEvents.value.length)
const blockedCount = computed(() => filteredEvents.value.filter(e => e.blocked).length)
const commandCount = computed(() => filteredEvents.value.filter(e => e.command).length)
const uniqueUsers = computed(() => {
  const set = new Set(filteredEvents.value.map(e => e.username))
  return set.size
})

const formatTime = (ts: string) => {
  if (!ts) return ''
  return new Date(ts).toLocaleString('zh-CN')
}

const loadData = () => {
  bastionStore.loadAudit({
    user: filterUser.value || undefined,
    session: filterSession.value || undefined,
  })
}

const applyFilters = () => {
  loadData()
}

onMounted(() => {
  loadData()
})
</script>

<style scoped>
.audit-page {
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
  color: var(--text-primary);
}

.filter-controls {
  display: flex;
  gap: 10px;
  align-items: center;
}

.stat-box {
  text-align: center;
  padding: 15px;
}

.stat-value {
  font-size: 28px;
  font-weight: bold;
  color: var(--text-primary);
}

.stat-label {
  font-size: 13px;
  color: var(--text-disabled);
  margin-top: 4px;
}

.stat-danger {
  color: #ff6b6b;
}

.stat-primary {
  color: var(--el-color-primary);
}
</style>