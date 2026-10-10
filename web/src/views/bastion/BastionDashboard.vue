<template>
  <div class="dashboard-page">
    <el-alert
      v-if="!bastionStore.bastionEnabled"
      :title="bastionStore.bastionError || 'SSH bastion is not enabled'"
      type="warning"
      style="margin-bottom: 20px;"
    />
    <div class="page-header">
      <h2 class="page-title">堰垒机概览</h2>
      <el-button type="primary" :loading="loading" :disabled="!bastionStore.bastionEnabled" @click="loadData">
        <RefreshRight />
        刷新
      </el-button>
    </div>

    <!-- Status cards -->
    <el-row :gutter="20" style="margin-bottom: 20px;">
      <el-col :span="6">
        <el-card shadow="hover">
          <div class="stat-card">
            <div class="stat-value">{{ bastionStore.userCount }}</div>
            <div class="stat-label">用户总数</div>
          </div>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card shadow="hover">
          <div class="stat-card">
            <div class="stat-value">{{ bastionStore.assetCount }}</div>
            <div class="stat-label">资产总数</div>
          </div>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card shadow="hover">
          <div class="stat-card">
            <div class="stat-value">{{ bastionStore.activeSessions.length }}</div>
            <div class="stat-label">活跃会话</div>
            <div class="stat-sub">{{ bastionStore.totalSessions }} 总会话</div>
          </div>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card shadow="hover">
          <div class="stat-card">
            <div class="stat-value">{{ bastionStore.bannedCommands.length }}</div>
            <div class="stat-label">禁止命令</div>
            <div class="stat-sub">{{ bastionStore.bastionEnabled ? '服务正常' : '服务未启用' }}</div>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <!-- Active sessions -->
    <el-card style="margin-bottom: 20px;">
      <div slot="header">
        <span>活跃会话</span>
      </div>
      <el-table :data="bastionStore.activeSessions" style="width: 100%" v-loading="loading">
        <el-table-column prop="id" label="会话 ID" width="180" />
        <el-table-column prop="username" label="用户" width="120" />
        <el-table-column prop="asset_name" label="资产" />
        <el-table-column prop="start_time" label="开始时间" width="160">
          <template #default="scope">
            {{ formatTime(scope.row.start_time) }}
          </template>
        </el-table-column>
        <el-table-column label="状态" width="100">
          <template #default="scope">
            <el-tag type="success">活跃</el-tag>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <!-- Recent audit events -->
    <el-card>
      <div slot="header">
        <span>最近审计事件</span>
      </div>
      <el-table :data="recentAuditEvents" style="width: 100%" v-loading="loading">
        <el-table-column prop="timestamp" label="时间" width="160">
          <template #default="scope">
            {{ formatTime(scope.row.timestamp) }}
          </template>
        </el-table-column>
        <el-table-column prop="username" label="用户" width="120" />
        <el-table-column prop="command" label="命令" />
        <el-table-column prop="action" label="操作" width="100">
          <template #default="scope">
            <el-tag :type="scope.row.blocked ? 'danger' : 'info'">
              {{ scope.row.blocked ? '阻止' : scope.row.action }}
            </el-tag>
          </template>
        </el-table-column>
      </el-table>
    </el-card>
  </div>
</template>

<script lang="ts" setup>
import { ref, onMounted, computed } from 'vue'
import { useBastionStore } from '@/stores/bastion'
import { RefreshRight } from '@element-plus/icons-vue'

const bastionStore = useBastionStore()
const loading = ref(false)

const recentAuditEvents = computed(() => {
  return bastionStore.auditEvents.slice(-10).reverse()
})

const formatTime = (ts: string) => {
  if (!ts) return ''
  return new Date(ts).toLocaleString('zh-CN', {
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  })
}

const loadData = async () => {
  loading.value = true
  try {
    await bastionStore.loadHealth()
    if (bastionStore.bastionEnabled) {
      await bastionStore.loadSessions()
      await bastionStore.loadAudit()
    }
  } catch (e) {
    console.error(e)
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  loadData()
})
</script>

<style scoped>
.dashboard-page {
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

.stat-card {
  text-align: center;
  padding: 10px;
}

.stat-value {
  font-size: 28px;
  font-weight: bold;
  color: #409EFF;
}

.stat-label {
  font-size: 13px;
  color: var(--text-disabled);
  margin-top: 4px;
}

.stat-sub {
  font-size: 11px;
  color: var(--text-secondary);
  margin-top: 2px;
}
</style>
