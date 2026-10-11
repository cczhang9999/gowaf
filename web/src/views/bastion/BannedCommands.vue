<template>
  <div class="banned-page">
    <el-alert
      v-if="!bastionStore.bastionEnabled"
      :title="bastionStore.bastionError || 'SSH bastion is not enabled'"
      type="warning"
      style="margin-bottom: 20px;"
    />
    <div class="page-header">
      <h2 class="page-title">禁止命令</h2>
      <el-button type="primary" :disabled="!bastionStore.bastionEnabled" @click="showDialog = true">
        <Plus />
        添加规则
      </el-button>
    </div>

    <el-card>
      <el-table :data="bastionStore.bannedCommands" style="width: 100%" v-loading="bastionStore.loading">
        <el-table-column prop="id" label="ID" width="140" />
        <el-table-column prop="pattern" label="匹配模式" width="200" />
        <el-table-column prop="reason" label="原因" />
        <el-table-column prop="enabled" label="状态" width="100">
          <template #default="scope">
            <el-tag :type="scope.row.enabled ? 'success' : 'info'">
              {{ scope.row.enabled ? '启用' : '禁用' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="160" fixed="right">
          <template #default="scope">
            <el-button
              size="small"
              :type="scope.row.enabled ? 'warning' : 'success'"
              @click="toggleCommand(scope.row)"
            >
              {{ scope.row.enabled ? '禁用' : '启用' }}
            </el-button>
            <el-button size="small" type="danger" @click="deleteCommand(scope.row)">
              <Delete />
              删除
            </el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <!-- Add Command Dialog -->
    <el-dialog v-model="showDialog" :title="dialogTitle" @closed="showDialog = false">
      <el-form :model="form" label-width="100px">
        <el-form-item label="ID" required>
          <el-input v-model="form.id" placeholder="规则 ID,如: ban-009" />
        </el-form-item>
        <el-form-item label="匹配模式" required>
          <el-input v-model="form.pattern" placeholder="匹配关键词/模式(不区分大小写)" />
        </el-form-item>
        <el-form-item label="原因">
          <el-input v-model="form.reason" placeholder="为什么禁止这个命令" />
        </el-form-item>
        <el-form-item label="状态">
          <el-switch
            v-model="form.enabled"
            active-text="启用"
            inactive-text="禁用"
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showDialog = false">取消</el-button>
        <el-button type="primary" @click="saveCommand">保存</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script lang="ts" setup>
import { ref, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Plus, Delete } from '@element-plus/icons-vue'
import { useBastionStore } from '@/stores/bastion'
import type { BastionBannedCommand } from '@/stores/bastion'

const bastionStore = useBastionStore()
const showDialog = ref(false)

const form = ref({
  id: '',
  pattern: '',
  reason: '',
  enabled: true,
})

const dialogTitle = '添加禁止命令规则'

const loadData = () => {
  bastionStore.loadBannedCommands()
}

const saveCommand = async () => {
  if (!form.value.id) {
    form.value.id = 'ban-' + Date.now().toString().slice(-5)
  }
  if (!form.value.pattern) {
    // Can't use ElMessage without import, but we can alert
    alert('请输入匹配模式')
    return
  }
  try {
    await bastionStore.addBannedCommand({
      id: form.value.id,
      pattern: form.value.pattern,
      reason: form.value.reason,
      enabled: form.value.enabled,
    } as BastionBannedCommand)
    // Reset and close
    form.value = { id: '', pattern: '', reason: '', enabled: true }
    showDialog.value = false
  } catch (e: any) {
    alert(e?.message || '保存失败')
  }
}

const toggleCommand = (cmd: BastionBannedCommand) => {
  // Toggle enabled state (note: in full implementation, this would call an API endpoint)
  cmd.enabled = !cmd.enabled
  // In a real implementation, you'd call an API to update this
  // For now, we just show a message
}

const deleteCommand = async (cmd: BastionBannedCommand) => {
  try {
    await ElMessageBox.confirm(`删除禁止命令规则 "${cmd.pattern}" 吗？`, '删除确认', {
      type: 'warning',
    })
    // In a real implementation, you'd call an API to delete this
    // For now, we just remove from the list locally
    const idx = bastionStore.bannedCommands.indexOf(cmd)
    if (idx >= 0) {
      bastionStore.bannedCommands.splice(idx, 1)
    }
  } catch {
    // Cancelled
  }
}

onMounted(() => {
  loadData()
})
</script>

<style scoped>
.banned-page {
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
</style>
