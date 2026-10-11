<template>
  <div class="assets-page">
    <el-alert
      v-if="!bastionStore.bastionEnabled"
      :title="bastionStore.bastionError || 'SSH bastion is not enabled'"
      type="warning"
      style="margin-bottom: 20px;"
    />
    <div class="page-header">
      <h2 class="page-title">资产管理</h2>
      <el-button type="primary" :disabled="!bastionStore.bastionEnabled" @click="showDialog = true">
        <Plus />
        添加资产
      </el-button>
    </div>

    <el-card>
      <el-table :data="bastionStore.assets" style="width: 100%" v-loading="bastionStore.loading">
        <el-table-column prop="name" label="名称" width="140" />
        <el-table-column prop="hostname" label="主机名/IP" width="160" />
        <el-table-column prop="port" label="端口" width="80" />
        <el-table-column prop="username" label="用户" width="100" />
        <el-table-column prop="comment" label="描述" />
        <el-table-column prop="created_at" label="添加时间" width="160">
          <template #default="scope">
            {{ formatTime(scope.row.created_at) }}
          </template>
        </el-table-column>
        <el-table-column label="操作" width="200" fixed="right">
          <template #default="scope">
            <el-button size="small" type="primary" @click="editAsset(scope.row)">
              <Edit />
              编辑
            </el-button>
            <el-button size="small" type="danger" @click="deleteAsset(scope.row)">
              <Delete />
              删除
            </el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <!-- Add/Edit Asset Dialog -->
    <el-dialog v-model="showDialog" :title="dialogTitle" @closed="showDialog = false">
      <el-form :model="form" label-width="100px">
        <el-form-item label="名称" required>
          <el-input v-model="form.name" placeholder="资产名称,如:生产-web-01" />
        </el-form-item>
        <el-form-item label="主机名/IP" required>
          <el-input v-model="form.hostname" placeholder="IP 地址或 DNS 名称" />
        </el-form-item>
        <el-form-item label="端口">
          <el-input-number v-model="form.port" :min="1" :max="65535" :precision="0" />
        </el-form-item>
        <el-form-item label="用户名">
          <el-input v-model="form.username" placeholder="SSH 用户名,留空使用默认" />
        </el-form-item>
        <el-form-item label="密码">
          <el-input v-model="form.password" type="password" placeholder="SSH 密码" />
        </el-form-item>
        <el-form-item label="私钥文件">
          <el-input v-model="form.private_key_file" placeholder="如: /root/.ssh/id_rsa (选填)" />
        </el-form-item>
        <el-form-item label="描述">
          <el-input v-model="form.comment" type="textarea" :rows="2" placeholder="备注信息" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showDialog = false">取消</el-button>
        <el-button type="primary" @click="saveAsset">保存</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script lang="ts" setup>
import { ref, computed, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Plus, Edit, Delete } from '@element-plus/icons-vue'
import { useBastionStore } from '@/stores/bastion'
import type { BastionAsset, BastionAssetCreate, BastionAssetUpdate } from '@/stores/bastion'

const bastionStore = useBastionStore()
const showDialog = ref(false)
const editingAsset = ref<BastionAsset | null>(null)

const form = ref({
  name: '',
  hostname: '',
  port: 22,
  username: '',
  password: '',
  private_key_file: '',
  comment: '',
})

const dialogTitle = computed(() => {
  return editingAsset.value ? '编辑资产' : '添加资产'
})

const formatTime = (ts: string) => {
  if (!ts) return ''
  return new Date(ts).toLocaleString('zh-CN')
}

const resetForm = () => {
  form.value = {
    name: '',
    hostname: '',
    port: 22,
    username: '',
    password: '',
    private_key_file: '',
    comment: '',
  }
  editingAsset.value = null
}

const showDialogFn = () => {
  showDialog.value = true
}

const editAsset = (asset: BastionAsset) => {
  editingAsset.value = { ...asset }
  form.value = {
    name: asset.name,
    hostname: asset.hostname,
    port: asset.port,
    username: asset.username,
    password: '',
    private_key_file: asset.private_key_file || '',
    comment: asset.comment || '',
  }
  showDialog.value = true
}

const deleteAsset = async (asset: BastionAsset) => {
  try {
    await ElMessageBox.confirm(`删除资产 "${asset.name}" 吗？`, '删除确认', {
      type: 'warning',
      inputType: 'text',
    })
    await bastionStore.deleteAsset(asset.id)
    ElMessage.success('已删除')
  } catch {
    // Cancelled
  }
}

const saveAsset = async () => {
  if (!form.value.hostname) {
    ElMessage.error('请输入主机名/IP')
    return
  }
  if (!form.value.name) {
    form.value.name = form.value.hostname
  }

  try {
    if (editingAsset.value) {
      await bastionStore.updateAsset(editingAsset.value.id, form.value as unknown as BastionAssetUpdate)
      ElMessage.success('已更新')
    } else {
      await bastionStore.createAsset(form.value as unknown as BastionAssetCreate)
      ElMessage.success('已添加')
    }
    showDialog.value = false
    resetForm()
  } catch (error: any) {
    ElMessage.error(error?.message || '保存失败')
  }
}

onMounted(() => {
  bastionStore.loadAssets()
})
</script>

<style scoped>
.assets-page {
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
