<template>
  <div class="page-wrapper">
    <div class="page-head">
      <div class="page-head__text">
        <h2 class="page-title">规则管理</h2>
        <div class="page-subtitle">
          <span>共 {{ wafStore.rules.length }} 条规则</span>
          <span class="source-chip">Go RE2 正则 · 支持 SIGHUP 热加载</span>
        </div>
      </div>
      <div class="page-head__actions">
        <el-button type="primary" @click="handleCreate">
          <template #icon>
            <Plus />
          </template>
          添加规则
        </el-button>
      </div>
    </div>

    <div class="toolbar">
      <el-input
        v-model="keyword"
        placeholder="搜索规则 ID / 正则"
        clearable
        style="width: 240px"
      >
        <template #prefix><el-icon><Search /></el-icon></template>
      </el-input>
      <el-select v-model="categoryFilter" placeholder="全部类别" clearable style="width: 170px">
        <el-option
          v-for="c in categoryOptions"
          :key="c"
          :label="c"
          :value="c"
        />
      </el-select>
      <el-button v-if="keyword || categoryFilter" link type="primary" @click="clearFilters">
        清除筛选
      </el-button>
      <div class="toolbar__spacer" />
      <span class="toolbar__count">显示 {{ filteredRules.length }} / {{ wafStore.rules.length }} 条</span>
    </div>

    <div class="panel">
      <el-table
        :data="filteredRules"
        class="w-full"
        :row-key="(row: Rule) => row.id"
      >
        <el-table-column prop="id" label="规则 ID" width="150" />
        <el-table-column prop="category" label="类别" width="140">
          <template #default="scope">
            <el-tag :type="getCategoryTag(scope.row.category)" effect="light">
              {{ scope.row.category }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="where" label="检测位置" width="150" />
        <el-table-column prop="pattern" label="正则表达式" min-width="300" show-overflow-tooltip>
          <template #default="scope">
            <code class="pattern-code">{{ scope.row.pattern }}</code>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="180" fixed="right">
          <template #default="scope">
            <div class="table-actions">
              <el-button size="small" @click="handleEdit(scope.row)">
                <el-icon><Edit /></el-icon>
                编辑
              </el-button>
              <el-button
                size="small"
                type="danger"
                plain
                @click="handleDelete(scope.row)"
                v-if="scope.row.id !== 'scan-001'"
              >
                <el-icon><Delete /></el-icon>
                删除
              </el-button>
            </div>
          </template>
        </el-table-column>

        <template #empty>
          <div class="empty-state">
            <div class="empty-state__icon">🛡️</div>
            <div class="empty-state__title">
              {{ keyword || categoryFilter ? '没有匹配的规则' : '暂无规则' }}
            </div>
            <div class="empty-state__hint">
              {{ keyword || categoryFilter ? '试试调整搜索条件或类别筛选' : '点击右上角「添加规则」新建一条检测规则' }}
            </div>
          </div>
        </template>
      </el-table>
    </div>

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
import { Plus, Search, Edit, Delete } from '@element-plus/icons-vue'
import { useWafStore, type Rule } from '@/stores/waf'

const wafStore = useWafStore()

const showDialog = ref(false)
const editingRule = ref<Rule | null>(null)
const keyword = ref('')
const categoryFilter = ref('')

const categoryOptions = [
  'sqli', 'xss', 'path_traversal', 'cmd_injection',
  'rce', 'scanner', 'admin_probe', 'other',
]

const filteredRules = computed(() => {
  const kw = keyword.value.trim().toLowerCase()
  return wafStore.rules.filter((r) => {
    if (categoryFilter.value && r.category !== categoryFilter.value) return false
    if (!kw) return true
    return (
      r.id.toLowerCase().includes(kw) ||
      (r.pattern || '').toLowerCase().includes(kw)
    )
  })
})

const clearFilters = () => {
  keyword.value = ''
  categoryFilter.value = ''
}

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

