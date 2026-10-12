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
        <h2 class="page-title">堡垒机概览</h2>
        <div class="page-subtitle">
          <span class="source-chip" :class="{ 'is-live': bastionStore.bastionEnabled }">
            <el-icon><Connection /></el-icon>
            {{ bastionStore.bastionEnabled ? '服务正常' : '服务未启用' }}
          </span>
          <span v-if="bastionStore.health.uptime">运行时长 {{ formatUptime(bastionStore.health.uptime) }}</span>
        </div>
      </div>
      <div class="page-head__actions">
        <el-button :loading="loading" @click="loadData">
          <el-icon><RefreshRight /></el-icon>
          刷新
        </el-button>
      </div>
    </div>

    <!-- 状态磁贴 -->
    <div class="stat-grid">
      <div class="stat-tile">
        <div class="stat-tile__icon tone-brand"><el-icon><User /></el-icon></div>
        <div class="stat-tile__body">
          <div class="stat-tile__value">{{ bastionStore.userCount }}</div>
          <div class="stat-tile__label">用户总数</div>
        </div>
      </div>
      <div class="stat-tile">
        <div class="stat-tile__icon tone-purple"><el-icon><Monitor /></el-icon></div>
        <div class="stat-tile__body">
          <div class="stat-tile__value">{{ bastionStore.assetCount }}</div>
          <div class="stat-tile__label">资产总数</div>
        </div>
      </div>
      <div class="stat-tile">
        <div class="stat-tile__icon tone-success"><el-icon><Connection /></el-icon></div>
        <div class="stat-tile__body">
          <div class="stat-tile__value">{{ bastionStore.activeSessions.length }}</div>
          <div class="stat-tile__label">活跃会话 · 共 {{ bastionStore.totalSessions }}</div>
        </div>
      </div>
      <div class="stat-tile">
        <div class="stat-tile__icon tone-warning"><el-icon><Warning /></el-icon></div>
        <div class="stat-tile__body">
          <div class="stat-tile__value">{{ bastionStore.bannedCommands.length }}</div>
          <div class="stat-tile__label">禁止命令</div>
        </div>
      </div>
    </div>

    <!-- 活跃会话 -->
    <div class="panel gap-card">
      <div class="panel__head">
        <span class="panel__title">活跃会话</span>
        <el-tag type="success" effect="light">{{ bastionStore.activeSessions.length }} 个</el-tag>
      </div>
      <el-table :data="bastionStore.activeSessions" style="width: 100%" v-loading="loading">
        <el-table-column prop="id" label="会话 ID" width="200" />
        <el-table-column prop="username" label="用户" width="140" />
        <el-table-column prop="asset_name" label="资产" min-width="160" />
        <el-table-column label="开始时间" width="180">
          <template #default="scope">
            {{ formatTime(scope.row.start_time) }}
          </template>
        </el-table-column>
        <el-table-column label="状态" width="100">
          <template #default>
            <el-tag type="success" effect="light">活跃</el-tag>
          </template>
        </el-table-column>
        <template #empty>
          <div class="empty-state">
            <div class="empty-state__icon">🔌</div>
            <div class="empty-state__title">当前没有活跃会话</div>
            <div class="empty-state__hint">用户通过 SSH 登录后会显示在这里</div>
          </div>
        </template>
      </el-table>
    </div>

    <!-- 最近审计事件 -->
    <div class="panel gap-card">
      <div class="panel__head">
        <span class="panel__title">最近审计事件</span>
        <span class="toolbar__count">最近 {{ recentAuditEvents.length }} 条</span>
      </div>
      <el-table :data="recentAuditEvents" style="width: 100%" v-loading="loading">
        <el-table-column label="时间" width="180">
          <template #default="scope">
            {{ formatTime(scope.row.timestamp) }}
          </template>
        </el-table-column>
        <el-table-column prop="username" label="用户" width="140" />
        <el-table-column prop="command" label="命令" min-width="200" show-overflow-tooltip>
          <template #default="scope">
            <span class="mono">{{ scope.row.command || '—' }}</span>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="100">
          <template #default="scope">
            <el-tag :type="scope.row.blocked ? 'danger' : 'info'" effect="light">
              {{ scope.row.blocked ? '已阻止' : scope.row.action }}
            </el-tag>
          </template>
        </el-table-column>
        <template #empty>
          <div class="empty-state">
            <div class="empty-state__icon">📝</div>
            <div class="empty-state__title">暂无审计事件</div>
            <div class="empty-state__hint">用户执行命令后会记录在此</div>
          </div>
        </template>
      </el-table>
    </div>
  </div>
</template>

<script lang="ts" setup>
import { ref, onMounted, computed } from 'vue'
import { RefreshRight, Connection, User, Monitor, Warning } from '@element-plus/icons-vue'
import { useBastionStore } from '@/stores/bastion'

const bastionStore = useBastionStore()
const loading = ref(false)

const recentAuditEvents = computed(() => {
  return bastionStore.auditEvents.slice(-10).reverse()
})

const formatTime = (ts: string) => {
  if (!ts) return '—'
  const d = new Date(ts)
  if (Number.isNaN(d.getTime())) return '—'
  return d.toLocaleString('zh-CN', {
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  })
}

// 后端 healthz 的 uptime 是 Go duration 原始串(如 "8m19.90227209s"),转成中文可读格式
const formatUptime = (raw?: string) => {
  if (!raw) return ''
  const re = /(\d+(?:\.\d+)?)(h|m|s)/g
  let h = 0
  let m = 0
  let s = 0
  let match: RegExpExecArray | null
  while ((match = re.exec(raw)) !== null) {
    const n = parseFloat(match[1])
    if (match[2] === 'h') h = n
    else if (match[2] === 'm') m = n
    else s = n
  }
  const parts: string[] = []
  if (h) parts.push(`${h} 小时`)
  if (m) parts.push(`${Math.floor(m)} 分`)
  if (!h && s) parts.push(`${Math.round(s)} 秒`)
  return parts.length ? parts.join(' ') : raw
}

const loadData = async () => {
  loading.value = true
  try {
    await bastionStore.loadHealth()
    if (bastionStore.bastionEnabled !== false) {
      // 概览要展示用户/资产/禁止命令数量,这里一次性拉全
      await Promise.all([
        bastionStore.loadUsers(),
        bastionStore.loadAssets(),
        bastionStore.loadSessions(),
        bastionStore.loadBannedCommands(),
        bastionStore.loadAudit(),
      ])
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
