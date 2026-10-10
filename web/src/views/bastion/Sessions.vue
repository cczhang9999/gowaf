<template>
  <div class="sessions-page">
    <el-alert
      v-if="!bastionStore.bastionEnabled"
      :title="bastionStore.bastionError || 'SSH bastion is not enabled'"
      type="warning"
      style="margin-bottom: 20px;"
    />
    <div class="page-header">
      <h2 class="page-title">会话记录</h2>
      <el-button type="primary" @click="loadData">
        <RefreshRight />
        刷新
      </el-button>
    </div>

    <el-card>
      <el-table :data="bastionStore.sessions" style="width: 100%" v-loading="bastionStore.loading">
        <el-table-column prop="id" label="会话 ID" width="180" />
        <el-table-column prop="username" label="用户" width="120" />
        <el-table-column prop="asset_name" label="资产" />
        <el-table-column prop="start_time" label="开始时间" width="160">
          <template #default="scope">
            {{ formatTime(scope.row.start_time) }}
          </template>
        </el-table-column>
        <el-table-column prop="duration" label="时长" width="100" />
        <el-table-column label="状态" width="100">
          <template #default="scope">
            <el-tag :type="scope.row.status === 'active' ? 'success' : 'info'">
              {{ scope.row.status === 'active' ? '活跃' : '已结束' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="录像" width="120">
          <template #default="scope">
            <el-button
              v-if="scope.row.recording_path"
              size="small"
              type="primary"
              link
              @click="downloadRecording(scope.row)"
            >
              <Download />
              下载
            </el-button>
            <span v-else class="text-disabled">无</span>
          </template>
        </el-table-column>
      </el-table>

      <div class="session-stats" v-if="totalCount > 0">
        <span class="stat-item">活跃: {{ activeCount }}</span>
        <span class="stat-item">已结束: {{ closedCount }}</span>
        <span class="stat-item">总计: {{ totalCount }}</span>
      </div>
    </el-card>
  </div>
</template>

<script lang="ts" setup>
import { computed, onMounted } from 'vue'
import { RefreshRight, Download } from '@element-plus/icons-vue'
import { useBastionStore } from '@/stores/bastion'
import type { BastionSession } from '@/stores/bastion'

const bastionStore = useBastionStore()

const activeCount = computed(() => bastionStore.activeSessions.length)
const closedCount = computed(() => bastionStore.closedSessions.length)
const totalCount = computed(() => bastionStore.totalSessions)

const formatTime = (ts: string) => {
  if (!ts) return ''
  return new Date(ts).toLocaleString('zh-CN')
}

const loadData = () => {
  bastionStore.loadSessions()
}

const downloadRecording = async (session: BastionSession) => {
  try {
    await bastionStore.downloadRecording(session.id)
  } catch (e) {
    // Error handled in store
  }
}

onMounted(() => {
  loadData()
})
</script>

<style scoped>
.sessions-page {
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

.session-stats {
  margin-top: 15px;
  display: flex;
  gap: 15px;
  align-items: center;
}

.stat-item {
  font-size: 14px;
  color: var(--text-secondary);
}

.text-disabled {
  color: var(--text-disabled);
}
</style>