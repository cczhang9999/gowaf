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
        <h2 class="page-title">会话记录</h2>
        <div class="page-subtitle">
          <span>共 {{ totalCount }} 个会话</span>
          <span class="source-chip">支持会话录像回放</span>
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
        <div class="stat-tile__icon tone-success"><el-icon><Connection /></el-icon></div>
        <div class="stat-tile__body">
          <div class="stat-tile__value">{{ activeCount }}</div>
          <div class="stat-tile__label">活跃会话</div>
        </div>
      </div>
      <div class="stat-tile">
        <div class="stat-tile__icon tone-info"><el-icon><Clock /></el-icon></div>
        <div class="stat-tile__body">
          <div class="stat-tile__value">{{ closedCount }}</div>
          <div class="stat-tile__label">已结束会话</div>
        </div>
      </div>
      <div class="stat-tile">
        <div class="stat-tile__icon tone-brand"><el-icon><DataLine /></el-icon></div>
        <div class="stat-tile__body">
          <div class="stat-tile__value">{{ totalCount }}</div>
          <div class="stat-tile__label">会话总数</div>
        </div>
      </div>
    </div>

    <div class="panel">
      <el-table :data="bastionStore.sessions" style="width: 100%" v-loading="bastionStore.loading">
        <el-table-column prop="id" label="会话 ID" width="200" />
        <el-table-column prop="username" label="用户" width="140" />
        <el-table-column prop="asset_name" label="资产" min-width="160" />
        <el-table-column label="开始时间" width="180">
          <template #default="scope">
            <span class="text-disabled">{{ formatTime(scope.row.start_time) }}</span>
          </template>
        </el-table-column>
        <el-table-column prop="duration" label="时长" width="110" />
        <el-table-column label="状态" width="110">
          <template #default="scope">
            <el-tag :type="scope.row.status === 'active' ? 'success' : 'info'" effect="light">
              {{ scope.row.status === 'active' ? '活跃' : '已结束' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="录像" width="130">
          <template #default="scope">
            <el-button
              v-if="scope.row.recording_path"
              size="small"
              type="primary"
              link
              @click="downloadRecording(scope.row)"
            >
              <el-icon><Download /></el-icon>
              下载
            </el-button>
            <span v-else class="text-disabled">无</span>
          </template>
        </el-table-column>

        <template #empty>
          <div class="empty-state">
            <div class="empty-state__icon">🗂️</div>
            <div class="empty-state__title">暂无会话记录</div>
            <div class="empty-state__hint">用户通过 SSH 登录堡垒机后，会话会记录在此</div>
          </div>
        </template>
      </el-table>
    </div>
  </div>
</template>

<script lang="ts" setup>
import { computed, onMounted } from 'vue'
import { RefreshRight, Download, Connection, Clock, DataLine } from '@element-plus/icons-vue'
import { useBastionStore } from '@/stores/bastion'
import type { BastionSession } from '@/stores/bastion'

const bastionStore = useBastionStore()

const activeCount = computed(() => bastionStore.activeSessions.length)
const closedCount = computed(() => bastionStore.closedSessions.length)
const totalCount = computed(() => bastionStore.totalSessions)

const formatTime = (ts: string) => {
  if (!ts) return '—'
  const d = new Date(ts)
  if (Number.isNaN(d.getTime())) return '—'
  return d.toLocaleString('zh-CN', {
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit',
  })
}

const loadData = () => {
  bastionStore.loadSessions()
}

const downloadRecording = async (session: BastionSession) => {
  try {
    await bastionStore.downloadRecording(session.id)
  } catch {
    // 错误已在 store 中处理
  }
}

onMounted(() => {
  loadData()
})
</script>
