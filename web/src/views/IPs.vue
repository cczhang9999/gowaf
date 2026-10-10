<template>
  <div class="page-wrapper">
    <div class="page-header">
      <h2 class="page-title">IP 列表管理</h2>
      <div class="action-group">
        <el-button type="success" @click="showAddIp('allow')">
          <template #icon>
            <Plus />
          </template>
          添加白名单
        </el-button>
        <el-button type="danger" @click="showAddIp('deny')">
          <template #icon>
            <Close />
          </template>
          添加黑名单
        </el-button>
      </div>
    </div>

    <el-tabs v-model="activeTab" @change="loadLists">
      <el-tab-pane name="allow" label="白名单">
        <div class="ips-section">
          <div class="ips-count">当前 {{ wafStore.allowList.length }} 个 IP/CIDR</div>
          <el-table :data="wafStore.allowList" class="w-full" height="300">
            <el-table-column label="IP/CIDR">
              <template #default="scope">
                {{ scope.row }}
              </template>
            </el-table-column>
            <el-table-column label="操作" width="120" fixed="right">
              <template #default="scope">
                <el-button size="small" type="danger" @click="removeFromAllow(scope.row)">
                  删除
                </el-button>
              </template>
            </el-table-column>
          </el-table>
        </div>
      </el-tab-pane>

      <el-tab-pane name="deny" label="黑名单">
        <div class="ips-section">
          <div class="ips-count">当前 {{ wafStore.denyList.length }} 个 IP/CIDR</div>
          <el-table :data="wafStore.denyList" style="width: 100%" height="300">
            <el-table-column label="IP/CIDR">
              <template #default="scope">
                {{ scope.row }}
              </template>
            </el-table-column>
            <el-table-column label="操作" width="120" fixed="right">
              <template #default="scope">
                <el-button size="small" type="danger" @click="removeFromDeny(scope.row)">
                  删除
                </el-button>
              </template>
            </el-table-column>
          </el-table>
        </div>
      </el-tab-pane>
    </el-tabs>

    <!-- 添加 IP 弹窗 -->
    <el-dialog :title="dialogTitle" v-model="showDialog" width="400px">
      <el-form :model="addForm" label-width="100px">
        <el-form-item label="IP/CIDR" required>
          <el-input
            v-model="addForm.ips"
            placeholder="示例: 192.168.1.1 或 10.0.0.0/8"
            type="textarea"
            :rows="3"
          />
          <div class="help-text">
            每行一个 IP 或 CIDR，可用逗号/分号分隔；支持 IPv4 和 IPv6，支持 # 注释
          </div>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showDialog = false">取消</el-button>
        <el-button type="primary" @click="addIp">添加</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script lang="ts" setup>
import { ref, computed, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import { Plus, Close } from '@element-plus/icons-vue'
import { useWafStore } from '@/stores/waf'
import { parseIpInput } from '@/utils/ip'

const wafStore = useWafStore()

const activeTab = ref('allow')
const showDialog = ref(false)
const addType = ref<'allow' | 'deny'>('allow')
const addForm = ref<{
  ips: string
}>({
  ips: '',
})

const dialogTitle = computed(() => {
  return addType.value === 'allow' ? '添加白名单 IP' : '添加黑名单 IP'
})

const loadLists = () => {
  wafStore.loadAllowList()
  wafStore.loadDenyList()
}

const showAddIp = (type: 'allow' | 'deny') => {
  addType.value = type
  addForm.value.ips = ''
  showDialog.value = true
}

const addIp = async () => {
  const { valid, invalid } = parseIpInput(addForm.value.ips)

  if (valid.length === 0) {
    if (invalid.length > 0) {
      ElMessage.error(`没有有效的 IP/CIDR：${invalid.join('，')}`)
    } else {
      ElMessage.warning('请输入有效的 IP 或 CIDR')
    }
    return
  }

  if (invalid.length > 0) {
    ElMessage.warning(`${invalid.length} 个条目无效，已忽略：${invalid.join('，')}`)
  }

  try {
    if (addType.value === 'allow') {
      await wafStore.addToAllowList(valid)
    } else {
      await wafStore.addToDenyList(valid)
    }
    ElMessage.success(`已添加 ${valid.length} 个 IP/CIDR`)
    showDialog.value = false
  } catch (error: any) {
    const detail = error?.response?.data?.error || error?.response?.data || error?.message
    ElMessage.error(typeof detail === 'string' ? detail : '添加失败，请检查输入后重试')
  }
}

const removeFromAllow = async (ip: string) => {
  try {
    await wafStore.removeFromAllowList([ip])
    ElMessage.success('已移除')
  } catch (error) {
    ElMessage.error('移除失败')
  }
}

const removeFromDeny = async (ip: string) => {
  try {
    await wafStore.removeFromDenyList([ip])
    ElMessage.success('已移除')
  } catch (error) {
    ElMessage.error('移除失败')
  }
}

onMounted(() => {
  loadLists()
})
</script>

<style scoped>
.ips-section {
  padding: 10px;
}

.ips-count {
  font-size: 14px;
  color: var(--text-secondary);
  margin-bottom: 10px;
  padding-bottom: 10px;
  border-bottom: 1px solid var(--border-color);
}
</style>