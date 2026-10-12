<template>
  <div class="page-wrapper">
    <el-alert
      v-if="bastionStore.bastionEnabled === false"
      :title="bastionStore.bastionError || 'SSH 堡垒机未启用，用户接口不可用'"
      type="warning"
      show-icon
      :closable="false"
      style="margin-bottom: 16px;"
    />

    <el-alert
      v-if="bastionStore.usersError"
      :title="`加载用户列表失败：${bastionStore.usersError}`"
      type="error"
      show-icon
      :closable="false"
      style="margin-bottom: 16px;"
    />

    <div class="page-head">
      <div class="page-head__text">
        <h2 class="page-title">用户管理</h2>
        <div class="page-subtitle">
          <span class="source-chip" :class="{ 'is-live': isDbBacked }">
            <el-icon><Coin /></el-icon>
            数据来源 {{ sourceLabel }}
          </span>
          <span>共 {{ bastionStore.userCount }} 个用户</span>
        </div>
      </div>
      <div class="page-head__actions">
        <el-button :loading="bastionStore.loading" @click="refresh">
          <el-icon><Refresh /></el-icon>
          刷新
        </el-button>
        <el-button type="primary" :disabled="bastionStore.bastionEnabled === false" @click="openCreate">
          <el-icon><Plus /></el-icon>
          添加用户
        </el-button>
      </div>
    </div>

    <!-- 统计磁贴:点击按角色筛选 -->
    <div class="stat-grid">
      <div
        class="stat-tile is-clickable"
        :class="{ 'is-active': roleFilter === '' }"
        @click="roleFilter = ''"
      >
        <div class="stat-tile__icon tone-brand"><el-icon><User /></el-icon></div>
        <div class="stat-tile__body">
          <div class="stat-tile__value">{{ bastionStore.userCount }}</div>
          <div class="stat-tile__label">全部用户</div>
        </div>
      </div>
      <div
        class="stat-tile is-clickable"
        :class="{ 'is-active': roleFilter === 'admin' }"
        @click="roleFilter = 'admin'"
      >
        <div class="stat-tile__icon tone-danger"><el-icon><Star /></el-icon></div>
        <div class="stat-tile__body">
          <div class="stat-tile__value">{{ bastionStore.adminCount }}</div>
          <div class="stat-tile__label">管理员</div>
        </div>
      </div>
      <div
        class="stat-tile is-clickable"
        :class="{ 'is-active': roleFilter === 'user' }"
        @click="roleFilter = 'user'"
      >
        <div class="stat-tile__icon tone-success"><el-icon><UserFilled /></el-icon></div>
        <div class="stat-tile__body">
          <div class="stat-tile__value">{{ bastionStore.normalUserCount }}</div>
          <div class="stat-tile__label">普通用户</div>
        </div>
      </div>
      <div
        class="stat-tile is-clickable"
        :class="{ 'is-active': roleFilter === 'auditor' }"
        @click="roleFilter = 'auditor'"
      >
        <div class="stat-tile__icon tone-warning"><el-icon><View /></el-icon></div>
        <div class="stat-tile__body">
          <div class="stat-tile__value">{{ bastionStore.auditorCount }}</div>
          <div class="stat-tile__label">审计员</div>
        </div>
      </div>
    </div>

    <!-- 工具条 -->
    <div class="toolbar">
      <el-input
        v-model="keyword"
        placeholder="搜索用户名 / 描述"
        clearable
        style="width: 240px"
      >
        <template #prefix><el-icon><Search /></el-icon></template>
      </el-input>
      <el-select v-model="roleFilter" placeholder="全部角色" clearable style="width: 150px">
        <el-option label="全部角色" value="" />
        <el-option label="管理员" value="admin" />
        <el-option label="普通用户" value="user" />
        <el-option label="审计员" value="auditor" />
      </el-select>
      <el-button v-if="keyword || roleFilter" link type="primary" @click="clearFilters">
        清除筛选
      </el-button>
      <div class="toolbar__spacer" />
      <span class="toolbar__count">显示 {{ filteredUsers.length }} / {{ bastionStore.userCount }} 条</span>
    </div>

    <div class="panel">
      <el-table
        :data="filteredUsers"
        style="width: 100%"
        v-loading="bastionStore.loading"
        :row-key="(row: BastionUser) => row.username"
      >
        <el-table-column label="用户" min-width="220">
          <template #default="scope">
            <div class="user-cell">
              <div class="avatar-initial">{{ initial(scope.row.username) }}</div>
              <div>
                <div class="user-cell__name">{{ scope.row.username }}</div>
                <div class="user-cell__id">
                  {{ scope.row.id != null ? `#${scope.row.id}` : '—' }}
                </div>
              </div>
            </div>
          </template>
        </el-table-column>

        <el-table-column prop="role" label="角色" width="120">
          <template #default="scope">
            <el-tag :type="roleTagType(scope.row.role)" effect="light">
              {{ roleLabel(scope.row.role) }}
            </el-tag>
          </template>
        </el-table-column>

        <el-table-column label="授权资产" width="150">
          <template #default="scope">
            <el-tooltip
              v-if="scope.row.assets && scope.row.assets.length"
              :content="scope.row.assets.join('、')"
              placement="top"
            >
              <el-tag type="info" effect="plain">{{ scope.row.assets.length }} 个资产</el-tag>
            </el-tooltip>
            <el-tag v-else type="success" effect="plain">全部资产</el-tag>
          </template>
        </el-table-column>

        <el-table-column label="描述" min-width="180" show-overflow-tooltip>
          <template #default="scope">
            <span :class="{ 'text-disabled': !scope.row.comment }">
              {{ scope.row.comment || '—' }}
            </span>
          </template>
        </el-table-column>

        <el-table-column label="创建时间" width="170">
          <template #default="scope">
            <span class="text-disabled">{{ formatTime(scope.row.created_at) }}</span>
          </template>
        </el-table-column>

        <el-table-column label="操作" width="170" fixed="right">
          <template #default="scope">
            <div class="table-actions">
              <el-button size="small" @click="openEdit(scope.row)">
                <el-icon><Edit /></el-icon>
                编辑
              </el-button>
              <el-button size="small" type="danger" plain @click="deleteUser(scope.row)">
                <el-icon><Delete /></el-icon>
                删除
              </el-button>
            </div>
          </template>
        </el-table-column>

        <template #empty>
          <div class="empty-state">
            <div class="empty-state__icon">👤</div>
            <div class="empty-state__title">
              {{ hasFilters ? '没有匹配的用户' : '暂无用户数据' }}
            </div>
            <div class="empty-state__hint">
              {{ hasFilters ? '试试调整搜索条件或角色筛选' : '点击右上角「添加用户」创建第一个用户' }}
            </div>
          </div>
        </template>
      </el-table>
    </div>

    <!-- 新增 / 编辑弹窗 -->
    <el-dialog
      v-model="showDialog"
      :title="dialogTitle"
      width="560px"
      @closed="resetForm"
    >
      <el-form ref="formRef" :model="form" :rules="rules" label-width="92px">
        <el-form-item label="用户名" prop="username">
          <el-input
            v-model="form.username"
            placeholder="登录名，唯一"
            :disabled="isEdit"
          />
        </el-form-item>
        <el-form-item label="密码" :prop="isEdit ? undefined : 'password'">
          <el-input
            v-model="form.password"
            type="password"
            show-password
            :placeholder="isEdit ? '留空表示不修改密码' : '至少 8 个字符'"
          />
        </el-form-item>
        <el-form-item label="角色" prop="role">
          <el-select v-model="form.role" style="width: 100%">
            <el-option label="管理员 (admin)" value="admin" />
            <el-option label="普通用户 (user)" value="user" />
            <el-option label="审计员 (auditor)" value="auditor" />
          </el-select>
        </el-form-item>
        <el-form-item label="授权资产">
          <el-select
            v-model="form.assets"
            multiple
            collapse-tags
            collapse-tags-tooltip
            placeholder="留空表示可访问全部资产"
            style="width: 100%"
          >
            <el-option
              v-for="asset in bastionStore.assets"
              :key="asset.id"
              :label="asset.name || asset.hostname"
              :value="asset.id"
            />
          </el-select>
          <div class="help-text">留空 = 全部资产；当前可选资产 {{ bastionStore.assets.length }} 个</div>
        </el-form-item>
        <el-form-item label="SSH 公钥">
          <el-input
            v-model="form.public_key"
            type="textarea"
            :rows="3"
            placeholder="选填，格式：ssh-ed25519 AAAA..."
          />
        </el-form-item>
        <el-form-item label="描述">
          <el-input v-model="form.comment" placeholder="备注信息，如岗位/姓名" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showDialog = false">取消</el-button>
        <el-button type="primary" :loading="saving" @click="saveUser">保存</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script lang="ts" setup>
import { ref, computed, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import type { FormInstance, FormRules } from 'element-plus'
import {
  Plus, Refresh, Edit, Delete, Search,
  User, UserFilled, Star, View, Coin,
} from '@element-plus/icons-vue'
import { useBastionStore } from '@/stores/bastion'
import type { BastionUser, BastionUserCreate, BastionUserUpdate, UserRole } from '@/stores/bastion'

const bastionStore = useBastionStore()

const showDialog = ref(false)
const saving = ref(false)
const editingUser = ref<BastionUser | null>(null)
const formRef = ref<FormInstance>()

const keyword = ref('')
const roleFilter = ref('')

interface UserForm {
  username: string
  password: string
  role: UserRole
  public_key: string
  assets: string[]
  comment: string
}

const emptyForm = (): UserForm => ({
  username: '',
  password: '',
  role: 'user',
  public_key: '',
  assets: [],
  comment: '',
})

const form = ref<UserForm>(emptyForm())

const isEdit = computed(() => !!editingUser.value)
const dialogTitle = computed(() => (isEdit.value ? '编辑用户' : '添加用户'))
const hasFilters = computed(() => !!(keyword.value || roleFilter.value))
const isDbBacked = computed(() => bastionStore.userStore.startsWith('mysql'))

// 展示用数据来源:后端返回 store=mysql(user1) 时,渲染成 MySQL · myapp.user1
const sourceLabel = computed(() => {
  const store = bastionStore.userStore
  const table = bastionStore.userTable || 'user1'
  if (!store) return '未知'
  if (store.startsWith('mysql')) return `MySQL · myapp.${table}`
  return store
})

const rules: FormRules = {
  username: [{ required: true, message: '请输入用户名', trigger: 'blur' }],
  password: [
    {
      validator: (_rule, value: string, cb) => {
        if (isEdit.value && !value) return cb()
        if (!value) return cb(new Error('请输入密码'))
        if (value.length < 8) return cb(new Error('密码至少 8 个字符'))
        cb()
      },
      trigger: 'blur',
    },
  ],
  role: [{ required: true, message: '请选择角色', trigger: 'change' }],
}

const filteredUsers = computed(() => {
  const kw = keyword.value.trim().toLowerCase()
  return bastionStore.users.filter((u) => {
    if (roleFilter.value && u.role !== roleFilter.value) return false
    if (!kw) return true
    return (
      u.username.toLowerCase().includes(kw) ||
      (u.comment || '').toLowerCase().includes(kw)
    )
  })
})

const initial = (name: string) => (name || '?').slice(0, 1)

const roleLabel = (role: string) => {
  const labels: Record<string, string> = { admin: '管理员', user: '普通用户', auditor: '审计员' }
  return labels[role] || role
}

const roleTagType = (role: string): 'danger' | 'primary' | 'warning' | 'info' => {
  const types: Record<string, 'danger' | 'primary' | 'warning' | 'info'> = {
    admin: 'danger',
    user: 'primary',
    auditor: 'warning',
  }
  return types[role] || 'info'
}

const formatTime = (ts: string) => {
  if (!ts) return '—'
  const d = new Date(ts)
  if (Number.isNaN(d.getTime())) return '—'
  return d.toLocaleString('zh-CN', {
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit',
  })
}

const clearFilters = () => {
  keyword.value = ''
  roleFilter.value = ''
}

const resetForm = () => {
  form.value = emptyForm()
  editingUser.value = null
  formRef.value?.clearValidate()
}

const refresh = () => {
  bastionStore.loadUsers()
  bastionStore.loadAssets()
}

const openCreate = () => {
  resetForm()
  showDialog.value = true
}

const openEdit = (user: BastionUser) => {
  editingUser.value = { ...user }
  form.value = {
    username: user.username,
    password: '',
    role: user.role,
    public_key: user.public_key || '',
    assets: user.assets || [],
    comment: user.comment || '',
  }
  showDialog.value = true
}

const deleteUser = async (user: BastionUser) => {
  try {
    await ElMessageBox.confirm(
      `确定删除用户「${user.username}」吗？此操作不可撤销。`,
      '删除确认',
      { type: 'warning', confirmButtonText: '删除', cancelButtonText: '取消' },
    )
  } catch {
    return // 取消
  }
  try {
    await bastionStore.deleteUser(user.username)
    ElMessage.success('已删除')
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || error?.message || '删除失败')
  }
}

const saveUser = async () => {
  if (!formRef.value) return
  const valid = await formRef.value.validate().catch(() => false)
  if (!valid) return

  saving.value = true
  try {
    if (isEdit.value && editingUser.value) {
      const update: BastionUserUpdate = {
        role: form.value.role,
        assets: form.value.assets,
      }
      // 仅在用户确实输入了新密码时才下发
      if (form.value.password) update.password = form.value.password
      // 指针字段:只有与已存值不同才发送(后端把空串视为「显式清空」)
      if (form.value.public_key !== (editingUser.value.public_key || '')) {
        update.public_key = form.value.public_key
      }
      if (form.value.comment !== (editingUser.value.comment || '')) {
        update.comment = form.value.comment
      }
      await bastionStore.updateUser(editingUser.value.username, update)
      ElMessage.success('已更新')
    } else {
      await bastionStore.createUser({
        username: form.value.username,
        password: form.value.password,
        role: form.value.role,
        public_key: form.value.public_key || undefined,
        assets: form.value.assets,
        comment: form.value.comment,
      } as BastionUserCreate)
      ElMessage.success('已添加')
    }
    showDialog.value = false
    resetForm()
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || error?.message || '保存失败')
  } finally {
    saving.value = false
  }
}

onMounted(() => {
  // 直接请求用户接口,不依赖 Layout 的健康检查结果
  bastionStore.loadUsers()
  bastionStore.loadAssets()
})
</script>
