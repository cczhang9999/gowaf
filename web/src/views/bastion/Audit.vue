<template>
  <div class="page-wrapper">
    <el-alert
      v-if="bastionStore.bastionEnabled === false"
      :title="bastionStore.bastionError || 'SSH 堡垒机未启用，启动时加 -ssh 参数即可开启'"
      type="warning"
      show-icon
      :closable="false"
      style="margin-bottom: 16px;"
    />

    <div class="page-head">
      <div class="page-head__text">
        <h2 class="page-title">命令审计</h2>
        <div class="page-subtitle">
          <span>记录会话内执行与被阻止的命令</span>
          <span class="source-chip">共 {{ totalCount }} 条事件</span>
        </div>
      </div>
      <div class="page-head__actions">
        <el-button :loading="bastionStore.loading" @click="loadData">
          <el-icon><RefreshRight /></el-icon>
          刷新
        </el-button>
      </div>
    </div>

    <div class="stat-grid">
      <div class="stat-tile">
        <div class="stat-tile__icon tone-brand"><el-icon><Document /></el-icon></div>
        <div class="stat-tile__body">
          <div class="stat-tile__value">{{ totalCount }}</div>
          <div class="stat-tile__label">总事件数</div>
        </div>
      </div>
      <div class="stat-tile">
        <div class="stat-tile__icon tone-danger"><el-icon><CircleCloseFilled /></el-icon></div>
        <div class="stat-tile__body">
          <div class="stat-tile__value">{{ blockedCount }}</div>
          <div class="stat-tile__label">阻止命令</div>
        </div>
      </div>
      <div class="stat-tile">
        <div class="stat-tile__icon tone-success"><el-icon><Aim /></el-icon></div>
        <div class="stat-tile__body">
          <div class="stat-tile__value">{{ commandCount }}</div>
          <div class="stat-tile__label">执行命令</div>
        </div>
      </div>
      <div class="stat-tile">
        <div class="stat-tile__icon tone-purple"><el-icon><User /></el-icon></div>
        <div class="stat-tile__body">
          <div class="stat-tile__value">{{ uniqueUsers }}</div>
          <div class="stat-tile__label">活跃用户</div>
        </div>
      </div>
    </div>

    <div class="toolbar">
      <el-input
        v-model="filterUser"
        placeholder="过滤用户名"
        clearable
        style="width: 180px"
        @input="applyFilters"
      >
        <template #prefix><el-icon><User /></el-icon></template>
      </el-input>
      <el-input
        v-model="filterSession"
        placeholder="过滤会话 ID"
        clearable
        style="width: 200px"
        @input="applyFilters"
      >
        <template #prefix><el-icon><Search /></el-icon></template>
      </el-input>
      <el-button v-if="filterUser || filterSession" link type="primary" @click="clearFilters">
        清除筛选
      </el-button>
      <div class="toolbar__spacer" />
      <span class="toolbar__count">显示 {{ filteredEvents.length }} 条</span>
    </div>

    <div class="panel">
      <el-table :data="filteredEvents" style="width: 100%" v-loading="bastionStore.loading">
        <el-table-column label="时间" width="180">
          <template #default="scope">
            <span class="text-disabled">{{ formatTime(scope.row.timestamp) }}</span>
          </template>
        </el-table-column>
        <el-table-column prop="username" label="用户" width="140" />
        <el-table-column prop="session_id" label="会话 ID" width="200" />
        <el-table-column label="命令" min-width="220" show-overflow-tooltip>
          <template #default="scope">
            <span class="mono">{{ scope.row.command || '—' }}</span>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="110">
          <template #default="scope">
            <el-tag :type="scope.row.blocked ? 'danger' : 'info'" effect="light">
              {{ scope.row.blocked ? '阻止' : scope.row.action }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="client_ip" label="客户端 IP" width="150">
          <template #default="scope">
            <span class="mono">{{ scope.row.client_ip || '—' }}</span>
          </template>
        </el-table-column>
        <el-table-column prop="rule_id" label="规则 ID" width="130">
          <template #default="scope">
            <span :class="{ 'text-disabled': !scope.row.rule_id }">{{ scope.row.rule_id || '—' }}</span>
          </template>
        </el-table-column>

        <template #empty>
          <div class="empty-state">
            <div class="empty-state__icon">🔍</div>
            <div class="empty-state__title">
              {{ filterUser || filterSession ? '没有匹配的审计事件' : '暂无审计事件' }}
            </div>
            <div class="empty-state__hint">
              {{ filterUser || filterSession ? '试试调整用户名或会话 ID 筛选' : '用户在会话中执行命令后会记录在此' }}
            </div>
          </div>
        </template>
      </el-table>
    </div>
  </div>
</template>

<script lang="ts" setup>
import { ref, computed, onMounted } from 'vue'
import {
  RefreshRight, Document, CircleCloseFilled, Aim, User, Search,
} from '@element-plus/icons-vue'
import { useBastionStore } from '@/stores/bastion'

const bastionStore = useBastionStore()
const filterUser = ref('')
const filterSession = ref('')

const filteredEvents = computed(() => {
  return bastionStore.auditEvents.filter(e => {
    if (filterUser.value && e.username !== filterUser.value) return false
    if (filterSession.value && !e.session_id?.includes(filterSession.value)) return false
    return true
  })
})

const totalCount = computed(() => filteredEvents.value.length)
const blockedCount = computed(() => filteredEvents.value.filter(e => e.blocked).length)
const commandCount = computed(() => filteredEvents.value.filter(e => e.command).length)
const uniqueUsers = computed(() => new Set(filteredEvents.value.map(e => e.username)).size)

const formatTime = (ts: string) => {
  if (!ts) return '—'
  const d = new Date(ts)
  if (Number.isNaN(d.getTime())) return '—'
  return d.toLocaleString('zh-CN', {
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  })
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

const clearFilters = () => {
  filterUser.value = ''
  filterSession.value = ''
  loadData()
}

onMounted(() => {
  loadData()
})
</script>
