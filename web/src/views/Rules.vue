<template>
  <div class="page-wrapper">
    <div class="page-header">
      <h2 class="page-title">规则管理</h2>
      <el-button type="primary" @click="handleCreate">
        <template #icon>
          <Plus />
        </template>
        添加规则
      </el-button>
    </div>

    <el-table :data="wafStore.rules" class="w-full" height="400" :row-key="row => row.id">
      <el-table-column prop="id" label="规则 ID" width="150" />
      <el-table-column prop="category" label="类别" width="120">
        <template #default="scope">
          <el-tag :type="getCategoryTag(scope.row.category)">
            {{ scope.row.category }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column prop="where" label="检测位置" width="150" />
      <el-table-column prop="pattern" label="正则表达式" width="300" show-overflow-tooltip />
      <el-table-column label="操作" width="180" fixed="right">
        <template #default="scope">
          <el-button size="small" @click="handleEdit(scope.row)">
            编辑
          </el-button>
          <el-button size="small" type="danger" @click="handleDelete(scope.row)" v-if="scope.row.id !== 'scan-001'">
            删除
          </el-button>
        </template>
      </el-table-column>
    </el-table>

    <!-- 规则编辑弹窗 -->
    <el-dialog :title="editingRule ? '编辑规则' : '添加规则'" v-model="showDialog" width="600px">
      <el-form :model="form" label-width="100px">
        <el-form-item label="规则 ID" required>
          <el-input v-model="form.id" placeholder="如: custom-001" />
        </el-form-item>
        <el-form-item label="类别" required>
          <el-select v-model="form.category" placeholder="请选择">
            <el-option label="sqli" value="sqli" />
            <el-option label="xss" value="xss" />
            <el-option label="path_traversal" value="path_traversal" />
            <el-option label="cmd_injection" value="cmd_injection" />
            <el-option label="rce" value="rce" />
            <el-option label="scanner" value="scanner" />
            <el-option label="admin_probe" value="admin_probe" />
            <el-option label="other" value="other" />
          </el-select>
        </el-form-item>
        <el-form-item label="检测位置">
          <el-select v-model="form.where" placeholder="全部位置">
            <el-option label="全部位置" value="" />
            <el-option label="URL 参数" value="query" />
            <el-option label="URL 路径" value="path" />
            <el-option label="请求体" value="body" />
            <el-option label="User-Agent" value="header:user-agent" />
            <el-option label="其它 Header" value="header:" />
          </el-select>
        </el-form-item>
        <el-form-item label="正则表达式" required>
          <el-input
            v-model="form.pattern"
            type="textarea"
            :rows="4"
            placeholder="Go RE2 正则表达式,需为小写"
          />
          <div class="help-text">
            说明: 正则会在 normalize 后的输入上匹配(多重 URL 解码、消除空格折叠、转小写)
          </div>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showDialog = false">取消</el-button>
        <el-button type="primary" @click="saveRule">确定</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script lang="ts" setup>
import { ref, computed } from 'vue'
import { ElMessageBox, ElMessage } from 'element-plus'
import { Plus } from '@element-plus/icons-vue'
import { useWafStore, type Rule } from '@/stores/waf'

const wafStore = useWafStore()

const showDialog = ref(false)
const editingRule = ref<Rule | null>(null)
const form = ref<{
  id: string
  category: string
  where: string
  pattern: string
}>({
  id: '',
  category: '',
  where: '',
  pattern: '',
})

const getCategoryTag = (category: string) => {
  const tags: Record<string, string> = {
    sqli: 'danger',
    xss: 'warning',
    path_traversal: 'info',
    cmd_injection: 'danger',
    rce: 'danger',
    scanner: 'info',
    admin_probe: 'primary',
    other: 'default',
  }
  return tags[category] || 'default'
}

const handleCreate = () => {
  editingRule.value = null
  form.value = {
    id: `custom-${Date.now().toString().slice(-3)}`,
    category: '',
    where: '',
    pattern: '',
  }
  showDialog.value = true
}

const handleEdit = (row: Rule) => {
  editingRule.value = row
  form.value = {
    id: row.id,
    category: row.category,
    where: row.where,
    pattern: row.pattern,
  }
  showDialog.value = true
}

const handleDelete = (row: Rule) => {
  ElMessageBox.confirm(
    `确定要删除规则 "${row.id}" 吗？`,
    '确认删除',
    {
      confirmButtonText: '删除',
      cancelButtonText: '取消',
      type: 'warning',
    },
  ).then(async () => {
    try {
      await wafStore.deleteRule(row.id)
      ElMessage.success('规则已删除')
    } catch (error) {
      ElMessage.error('删除失败')
    }
  })
}

const saveRule = async () => {
  if (!form.value.id || !form.value.category || !form.value.pattern) {
    ElMessage.error('请填写必填项')
    return
  }

  try {
    if (editingRule.value) {
      await wafStore.updateRule(editingRule.value.id, form.value)
      ElMessage.success('规则已更新')
    } else {
      await wafStore.createRules([form.value])
      ElMessage.success('规则已添加')
    }
    showDialog.value = false
  } catch (error) {
    ElMessage.error('操作失败')
  }
}
</script>

