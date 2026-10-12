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
        <h2 class="page-title">资产管理</h2>
        <div class="page-subtitle">
          <span>共 {{ bastionStore.assetCount }} 台资产</span>
          <span class="source-chip">用户授权按资产粒度控制</span>
        </div>
      </div>
      <div class="page-head__actions">
        <el-button type="primary" :disabled="bastionStore.bastionEnabled === false" @click="openCreate">
          <el-icon><Plus /></el-icon>
          添加资产
        </el-button>
      </div>
    </div>

    <div class="toolbar">
      <el-input v-model="keyword" placeholder="搜索名称 / 主机 / 描述" clearable style="width: 260px">
        <template #prefix><el-icon><Search /></el-icon></template>
      </el-input>
      <div class="toolbar__spacer" />
      <span class="toolbar__count">显示 {{ filteredAssets.length }} / {{ bastionStore.assetCount }} 台</span>
    </div>

    <div class="panel">
      <el-table :data="filteredAssets" style="width: 100%" v-loading="bastionStore.loading">
        <el-table-column label="名称" min-width="160">
          <template #default="scope">
            <span class="asset-name">{{ scope.row.name || scope.row.hostname }}</span>
          </template>
        </el-table-column>
        <el-table-column label="主机名 / IP" width="180">
          <template #default="scope">
            <span class="mono">{{ scope.row.hostname }}</span>
          </template>
        </el-table-column>
        <el-table-column prop="port" label="端口" width="90" />
        <el-table-column prop="username" label="用户" width="120">
          <template #default="scope">
            <span :class="{ 'text-disabled': !scope.row.username }">
              {{ scope.row.username || '默认' }}
            </span>
          </template>
        </el-table-column>
        <el-table-column label="描述" min-width="180" show-overflow-tooltip>
          <template #default="scope">
            <span :class="{ 'text-disabled': !scope.row.comment }">
              {{ scope.row.comment || '—' }}
            </span>
          </template>
        </el-table-column>
        <el-table-column label="添加时间" width="170">
          <template #default="scope">
            <span class="text-disabled">{{ formatTime(scope.row.created_at) }}</span>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="170" fixed="right">
          <template #default="scope">
            <div class="table-actions">
              <el-button size="small" @click="editAsset(scope.row)">
                <el-icon><Edit /></el-icon>
                编辑
              </el-button>
              <el-button size="small" type="danger" plain @click="deleteAsset(scope.row)">
                <el-icon><Delete /></el-icon>
                删除
              </el-button>
            </div>
          </template>
        </el-table-column>

        <template #empty>
          <div class="empty-state">
            <div class="empty-state__icon">🖥️</div>
            <div class="empty-state__title">
              {{ keyword ? '没有匹配的资产' : '暂无资产' }}
            </div>
            <div class="empty-state__hint">
              {{ keyword ? '试试调整搜索关键词' : '点击右上角「添加资产」登记一台可被堡垒机代理的服务器' }}
            </div>
          </div>
        </template>
      </el-table>
    </div>

    <!-- 新增 / 编辑资产弹窗 -->
    <el-dialog v-model="showDialog" :title="dialogTitle" width="560px" @closed="resetForm">
      <el-form :model="form" label-width="100px">
        <el-form-item label="名称" required>
          <el-input v-model="form.name" placeholder="资产名称，如：生产-web-01" />
        </el-form-item>
        <el-form-item label="主机名/IP" required>
          <el-input v-model="form.hostname" placeholder="IP 地址或 DNS 名称" />
        </el-form-item>
        <el-form-item label="端口">
          <el-input-number v-model="form.port" :min="1" :max="65535" :precision="0" />
        </el-form-item>
        <el-form-item label="用户名">
          <el-input v-model="form.username" placeholder="SSH 用户名，留空使用默认" />
        </el-form-item>
        <el-form-item label="密码">
          <el-input v-model="form.password" type="password" show-password placeholder="SSH 密码" />
        </el-form-item>
        <el-form-item label="私钥文件">
          <el-input v-model="form.private_key_file" placeholder="如：/root/.ssh/id_rsa（选填）" />
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
import { Plus, Edit, Delete, Search } from '@element-plus/icons-vue'
import { useBastionStore } from '@/stores/bastion'
import type { BastionAsset, BastionAssetCreate, BastionAssetUpdate } from '@/stores/bastion'

const bastionStore = useBastionStore()
const showDialog = ref(false)
const editingAsset = ref<BastionAsset | null>(null)
const keyword = ref('')

const emptyForm = () => ({
  name: '',
  hostname: '',
  port: 22,
  username: '',
  password: '',
  private_key_file: '',
  comment: '',
})

const form = ref(emptyForm())

const dialogTitle = computed(() => (editingAsset.value ? '编辑资产' : '添加资产'))

const filteredAssets = computed(() => {
  const kw = keyword.value.trim().toLowerCase()
  if (!kw) return bastionStore.assets
  return bastionStore.assets.filter((a) =>
    (a.name || '').toLowerCase().includes(kw) ||
    (a.hostname || '').toLowerCase().includes(kw) ||
    (a.comment || '').toLowerCase().includes(kw),
  )
})

const formatTime = (ts: string) => {
  if (!ts) return '—'
  const d = new Date(ts)
  if (Number.isNaN(d.getTime())) return '—'
  return d.toLocaleString('zh-CN', {
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit',
  })
}

const resetForm = () => {
  form.value = emptyForm()
  editingAsset.value = null
}

const openCreate = () => {
  resetForm()
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
    await ElMessageBox.confirm(
      `确定删除资产「${asset.name || asset.hostname}」吗？`,
      '删除确认',
      { type: 'warning', confirmButtonText: '删除', cancelButtonText: '取消' },
    )
  } catch {
    return // 取消
  }
  try {
    await bastionStore.deleteAsset(asset.id)
    ElMessage.success('已删除')
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || error?.message || '删除失败')
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
    ElMessage.error(error?.response?.data?.error || error?.message || '保存失败')
  }
}

onMounted(() => {
  bastionStore.loadAssets()
})
</script>

<style scoped>
.asset-name {
  font-weight: 600;
  color: var(--text-primary);
}
</style>
