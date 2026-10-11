<template>
  <div class="users-page">
    <el-alert
      v-if="bastionStore.bastionEnabled === false"
      :title="bastionStore.bastionError || 'SSH bastion is not enabled'"
      type="warning"
      style="margin-bottom: 20px;"
    />
    <div class="page-header">
      <h2 class="page-title">用户管理</h2>
      <el-button type="primary" :disabled="bastionStore.bastionEnabled === false" @click="showDialog = true">
        <Plus />
        添加用户
      </el-button>
    </div>

    <el-card>
      <el-table :data="bastionStore.users" style="width: 100%" v-loading="bastionStore.loading">
        <el-table-column prop="username" label="用户名" width="140" />
        <el-table-column prop="role" label="角色" width="100">
          <template #default="scope">
            <el-tag :type="roleTagType(scope.row.role)">
              {{ roleLabel(scope.row.role) }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="assets" label="授权资产" width="160">
          <template #default="scope">
            <span v-if="!scope.row.assets || scope.row.assets.length === 0" class="text-disabled">全部</span>
            <span v-else>{{ scope.row.assets.length }} 个</span>
          </template>
        </el-table-column>
        <el-table-column prop="comment" label="描述" />
        <el-table-column prop="created_at" label="创建时间" width="160">
          <template #default="scope">
            {{ formatTime(scope.row.created_at) }}
          </template>
        </el-table-column>
        <el-table-column label="操作" width="200" fixed="right">
          <template #default="scope">
            <el-button size="small" type="primary" @click="editUser(scope.row)">
              <Edit />
              编辑
            </el-button>
            <el-button size="small" type="danger" @click="deleteUser(scope.row)">
              <Delete />
              删除
            </el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <!-- Add/Edit User Dialog -->
    <el-dialog v-model="showDialog" :title="dialogTitle" @closed="resetForm">
      <el-form :model="form" label-width="100px">
        <el-form-item label="用户名" required :required="!isEdit">
          <el-input v-model="form.username" placeholder="用户名(登录名)" :disabled="isEdit" />
        </el-form-item>
        <el-form-item label="密码" required :required="!isEdit">
          <el-input v-model="form.password" type="password" placeholder="密码(至少 8 字符)" />
        </el-form-item>
        <el-form-item label="角色">
          <el-select v-model="form.role" placeholder="选择角色">
            <el-option label="管理员 (Admin)" value="admin" />
            <el-option label="用户 (User)" value="user" />
            <el-option label="审计员 (Auditor)" value="auditor" />
          </el-select>
        </el-form-item>
        <el-form-item label="公钥(选填)">
          <el-input
            v-model="form.public_key"
            type="textarea"
            :rows="3"
            placeholder="SSH 公钥,格式: ssh-rsa AAAAB3..."
          />
        </el-form-item>
        <el-form-item label="授权资产">
          <el-select
            v-model="form.assets"
            multiple
            placeholder="留空表示全部资产"
            style="width: 100%"
          >
            <el-option
              v-for="asset in bastionStore.assets"
              :key="asset.id"
              :label="asset.name || asset.hostname"
              :value="asset.id"
            />
          </el-select>
        </el-form-item>
        <el-form-item label="描述">
          <el-input v-model="form.comment" placeholder="备注信息" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showDialog = false">取消</el-button>
        <el-button type="primary" @click="saveUser">保存</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script lang="ts" setup>
import { ref, computed, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Plus, Edit, Delete } from '@element-plus/icons-vue'
import { useBastionStore } from '@/stores/bastion'
import type { BastionUser, BastionUserCreate, BastionUserUpdate, UserRole } from '@/stores/bastion'

const bastionStore = useBastionStore()
const showDialog = ref(false)
const editingUser = ref<BastionUser | null>(null)

const form = ref<UserForm>({
  username: '',
  password: '',
  role: 'user' as UserRole,
  public_key: '',
  assets: [],
  comment: '',
})

interface UserForm {
  username: string
  password: string
  role: UserRole
  public_key: string
  assets: string[]
  comment: string
}

const isEdit = computed(() => !!editingUser.value)

const dialogTitle = computed(() => {
  return editingUser.value ? '编辑用户' : '添加用户'
})

const roleLabel = (role: string) => {
  const labels: Record<string, string> = {
    admin: '管理员', user: '用户', auditor: '审计员',
  }
  return labels[role] || role
}

const roleTagType = (role: string) => {
  const types: Record<string, string> = {
    admin: 'danger', user: 'primary', auditor: 'warning',
  }
  return types[role] || 'info'
}

const formatTime = (ts: string) => {
  if (!ts) return ''
  return new Date(ts).toLocaleString('zh-CN')
}

const resetForm = () => {
  form.value = {
    username: '',
    password: '',
    role: 'user',
    public_key: '',
    assets: [],
    comment: '',
  }
  editingUser.value = null
}

const editUser = (user: BastionUser) => {
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
    await ElMessageBox.confirm(`删除用户 "${user.username}" 吗？`, '删除确认', {
      type: 'warning',
      inputType: 'text',
    })
    await bastionStore.deleteUser(user.username)
    ElMessage.success('已删除')
  } catch {
    // Cancelled
  }
}

const saveUser = async () => {
  if (!form.value.username) {
    ElMessage.error('请输入用户名')
    return
  }
  if (!isEdit.value && !form.value.password) {
    ElMessage.error('请输入密码')
    return
  }
  if (form.value.password && form.value.password.length < 8) {
    ElMessage.error('密码至少 8 个字符')
    return
  }

  try {
    if (isEdit.value && editingUser.value) {
      const update: BastionUserUpdate = {
        role: form.value.role,
        assets: form.value.assets,
      }
      // Only send a password when the user actually typed a new one.
      if (form.value.password) update.password = form.value.password
      // Send pointers as defined only when the value differs from the stored
      // value; the backend clears the field when the pointer is a nonzero
      // empty string, so explicit blanking is allowed here.
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
    ElMessage.error(error?.message || '保存失败')
  }
}

onMounted(() => {
  // Always hit the users API on enter — do not wait on Layout's health
  // check, which previously set bastionEnabled=false and skipped the request.
  bastionStore.loadUsers()
  bastionStore.loadAssets()
})
</script>

<style scoped>
.users-page {
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

.text-disabled {
  color: var(--text-disabled);
}
</style>
