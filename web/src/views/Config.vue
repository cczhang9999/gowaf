<template>
  <div class="config-page">
    <div class="page-header">
      <h2 class="page-title">配置管理</h2>
      <el-button type="primary" @click="saveConfig">
        保存配置
      </el-button>
    </div>

    <el-card>
      <template #header>
        <div class="card-title">基本设置</div>
      </template>
      <el-form :model="formData" label-width="100px">
        <el-form-item label="运行模式" required>
          <el-radio-group v-model="formData.mode">
            <el-radio value="block">拦截模式 (Block)</el-radio>
            <el-radio value="detect">检测模式 (Detect)</el-radio>
          </el-radio-group>
          <div class="help-text">
            - Block: 命中规则即拦截请求
            - Detect: 仅记录日志不拦截, 用于灰度观察新规则
          </div>
        </el-form-item>

        <el-form-item label="最大请求体">
          <el-input-number v-model="formData.maxBody" :min="1024" :step="1024" />
          <span class="unit"> 字节</span>
          <el-button @click="setMaxBody(1048576)">1MB</el-button>
          <el-button @click="setMaxBody(10485760)">10MB</el-button>
        </el-form-item>

        <el-form-item label="限流速率">
          <el-input-number v-model="formData.rps" :min="0" :step="1" />
          <span class="unit"> 请求/IP/秒</span>
          <div class="help-text">
            设置为 0 时禁用限流
          </div>
        </el-form-item>

        <el-form-item label="突发容量">
          <el-input-number v-model="formData.burst" :min="1" :step="1" />
          <span class="unit"> 次</span>
        </el-form-item>

        <el-form-item label="信任 X-Forwarded-For">
          <el-switch v-model="formData.trustXFF" />
          <div class="help-text">
            仅当 WAF 前面有可信代理时开启
          </div>
        </el-form-item>

        <el-form-item label="自动封禁设置">
          <el-row :gutter="10">
            <el-col :span="12">
              <el-input-number
                v-model="formData.banStrikes"
                :min="0"
                :step="1"
                label="违规次数"
              />
            </el-col>
            <el-col :span="12">
              <el-input-number
                v-model="formData.banForSeconds"
                :min="1"
                :step="1"
                label="封禁时长(秒)"
              />
            </el-col>
          </el-row>
        </el-form-item>
      </el-form>
    </el-card>

    <el-card style="margin-top: 20px">
      <template #header>
        <div class="card-title">高级设置</div>
      </template>
      <div class="advanced-section">
        <h4>日志级别</h4>
        <el-select v-model="formData.logLevel" placeholder="选择日志级别" style="width: 200px">
          <el-option label="info" value="info" />
          <el-option label="warn" value="warn" />
          <el-option label="error" value="error" />
        </el-select>
      </div>
    </el-card>
  </div>
</template>

<script lang="ts" setup>
import { ref, watch, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import { useWafStore } from '@/stores/waf'

const wafStore = useWafStore()

const formData = ref({
  mode: 'block',
  maxBody: 1048576,
  rps: 20,
  burst: 40,
  trustXFF: false,
  banStrikes: 5,
  banForSeconds: 600,
  logLevel: 'warn',
})

watch(
  () => formData.value,
  () => {
    // Sync with store
  },
)

// Load config from API
onMounted(() => {
  wafStore.loadConfig()
  watch(
    () => wafStore.config,
    (newConfig) => {
      if (newConfig) {
        formData.value = {
          mode: newConfig.mode,
          maxBody: newConfig.maxBody,
          rps: newConfig.rps,
          burst: newConfig.burst,
          trustXFF: newConfig.trustXFF,
          banStrikes: newConfig.banStrikes,
          banForSeconds: 600, // Default, would need backend support for duration parsing
          logLevel: 'warn',
        }
      }
    },
    { immediate: true },
  )
})

const setMaxBody = (bytes: number) => {
  formData.value.maxBody = bytes
}

const saveConfig = async () => {
  try {
    const config = {
      mode: formData.value.mode,
      maxBody: formData.value.maxBody,
      rps: formData.value.rps,
      burst: formData.value.burst,
      trustXFF: formData.value.trustXFF,
    }
    await wafStore.updateConfig(config)
    ElMessage.success('配置已保存')
  } catch (error) {
    ElMessage.error('保存失败')
  }
}
</script>

<style scoped>
.config-page {
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
  color: #303133;
}

.help-text {
  font-size: 12px;
  color: #909399;
  margin-top: 4px;
}

.unit {
  margin-left: 8px;
  color: #606266;
}

.card-title {
  font-weight: 600;
  color: #303133;
}

.advanced-section {
  padding: 10px 0;
}
</style>