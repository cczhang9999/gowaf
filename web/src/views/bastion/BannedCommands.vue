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
        <h2 class="page-title">禁止命令</h2>
        <div class="page-subtitle">
          <span>命中即拦截并记录审计</span>
          <span class="source-chip">共 {{ bastionStore.bannedCommands.length }} 条规则</span>
        </div>
      </div>
      <div class="page-head__actions">
        <el-button type="primary" :disabled="bastionStore.bastionEnabled === false" @click="openCreate">
          <el-icon><Plus /></el-icon>
          添加规则
        </el-button>
      </div>
    </div>

    <div class="toolbar">
      <el-input v-model="keyword" placeholder="搜索匹配模式 / 原因" clearable style="width: 260px">
        <template #prefix><el-icon><Search /></el-icon></template>
      </el-input>
      <div class="toolbar__spacer" />
      <span class="toolbar__count">显示 {{ filteredCommands.length }} / {{ bastionStore.bannedCommands.length }} 条</span>
    </div>

    <div class="panel">
      <el-table :data="filteredCommands" style="width: 100%" v-loading="bastionStore.loading">
        <el-table-column prop="id" label="ID" width="140" />
        <el-table-column label="匹配模式" min-width="200">
          <template #default="scope">
            <span class="mono">{{ scope.row.pattern }}</span>
          </template>
        </el-table-column>
        <el-table-column prop="reason" label="原因" min-width="180" show-overflow-tooltip>
          <template #default="scope">
            <span :class="{ 'text-disabled': !scope.row.reason }">{{ scope.row.reason || '—' }}</span>
          </template>
        </el-table-column>
        <el-table-column label="状态" width="100">
          <template #default="scope">
            <el-tag :type="scope.row.enabled ? 'success' : 'info'" effect="light">
              {{ scope.row.enabled ? '启用' : '禁用' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="180" fixed="right">
          <template #default="scope">
            <div class="table-actions">
              <el-button
                size="small"
                :type="scope.row.enabled ? 'warning' : 'success'"
                plain
                @click="toggleCommand(scope.row)"
              >
                {{ scope.row.enabled ? '禁用' : '启用' }}
              </el-button>
              <el-button size="small" type="danger" plain @click="deleteCommand(scope.row)">
                <el-icon><Delete /></el-icon>
                删除
              </el-button>
            </div>
          </template>
        </el-table-column>

        <template #empty>
          <div class="empty-state">
            <div class="empty-state__icon">🚫</div>
            <div class="empty-state__title">
              {{ keyword ? '没有匹配的规则' : '暂无禁止命令规则' }}
            </div>
            <div class="empty-state__hint">
              {{ keyword ? '试试调整搜索关键词' : '点击右上角「添加规则」定义需要拦截的危险命令' }}
            </div>
          </div>
        </template>
      </el-table>
    </div>

    <!-- 添加禁止命令弹窗 -->
    <el-dialog v-model="showDialog" title="添加禁止命令规则" width="520px" @closed="resetForm">
      <el-form ref="formRef" :model="form" :rules="rules" label-width="96px">
        <el-form-item label="规则 ID" prop="id">
          <el-input v-model="form.id" placeholder="留空自动生成，如：ban-009" />
        </el-form-item>
        <el-form-item label="匹配模式" prop="pattern">
          <el-input v-model="form.pattern" placeholder="匹配关键词/模式（不区分大小写）" />
        </el-form-item>
        <el-form-item label="原因">
          <el-input v-model="form.reason" placeholder="为什么禁止这个命令" />
        </el-form-item>
        <el-form-item label="状态">
          <el-switch v-model="form.enabled" active-text="启用" inactive-text="禁用" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showDialog = false">取消</el-button>
        <el-button type="primary" :loading="saving" @click="saveCommand">保存</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script lang="ts" setup>
import { ref, computed, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import type { FormInstance, FormRules } from 'element-plus'
import { Plus, Delete, Search } from '@element-plus/icons-vue'
import { useBastionStore } from '@/stores/bastion'
import type { BastionBannedCommand } from '@/stores/bastion'

const bastionStore = useBastionStore()
const showDialog = ref(false)
const saving = ref(false)
const keyword = ref('')
const formRef = ref<FormInstance>()

const emptyForm = () => ({ id: '', pattern: '', reason: '', enabled: true })
const form = ref(emptyForm())

const rules: FormRules = {
  pattern: [{ required: true, message: '请输入匹配模式', trigger: 'blur' }],
}

const filteredCommands = computed(() => {
  const kw = keyword.value.trim().toLowerCase()
  if (!kw) return bastionStore.bannedCommands
  return bastionStore.bannedCommands.filter((c) =>
    (c.pattern || '').toLowerCase().includes(kw) ||
    (c.reason || '').toLowerCase().includes(kw),
  )
})

const resetForm = () => {
  form.value = emptyForm()
  formRef.value?.clearValidate()
}

const openCreate = () => {
  resetForm()
  showDialog.value = true
}

const saveCommand = async () => {
  if (!formRef.value) return
  const valid = await formRef.value.validate().catch(() => false)
  if (!valid) return

  saving.value = true
  try {
    await bastionStore.addBannedCommand({
      id: form.value.id || `ban-${Date.now().toString().slice(-5)}`,
      pattern: form.value.pattern,
      reason: form.value.reason,
      enabled: form.value.enabled,
    } as BastionBannedCommand)
    ElMessage.success('已添加')
    showDialog.value = false
    resetForm()
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || error?.message || '保存失败')
  } finally {
    saving.value = false
  }
}

const toggleCommand = (cmd: BastionBannedCommand) => {
  // 后端暂未提供启停接口，这里只做前端展示态切换
  cmd.enabled = !cmd.enabled
  ElMessage.info(`已在本地${cmd.enabled ? '启用' : '禁用'}「${cmd.pattern}」（后端未持久化）`)
}

const deleteCommand = async (cmd: BastionBannedCommand) => {
  try {
    await ElMessageBox.confirm(
      `确定删除禁止命令规则「${cmd.pattern}」吗？`,
      '删除确认',
      { type: 'warning', confirmButtonText: '删除', cancelButtonText: '取消' },
    )
  } catch {
    return // 取消
  }
  // 后端暂未提供删除接口，这里只从本地列表移除
  const idx = bastionStore.bannedCommands.indexOf(cmd)
  if (idx >= 0) {
    bastionStore.bannedCommands.splice(idx, 1)
    ElMessage.success('已从列表移除（后端未持久化）')
  }
}

onMounted(() => {
  bastionStore.loadBannedCommands()
})
</script>
