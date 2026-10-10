<template>
  <div class="page-wrapper">
    <div class="page-header">
      <h2 class="page-title">配置管理</h2>
      <el-button type="primary" :loading="saving" @click="saveConfig">
        保存配置
      </el-button>
    </div>

    <el-card shadow="hover">
      <template #header>
        <div class="card-title">基本设置</div>
      </template>
      <el-form :model="formData" label-width="140px" :disabled="!configLoaded">
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
          <div class="help-text">设置为 0 时禁用限流</div>
        </el-form-item>

        <el-form-item label="突发容量">
          <el-input-number v-model="formData.burst" :min="1" :step="1" />
          <span class="unit"> 次</span>
        </el-form-item>

        <el-form-item label="信任 X-Forwarded-For">
          <el-switch v-model="formData.trustXFF" />
          <div class="help-text">仅当 WAF 前面有可信代理时开启</div>
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
              <div class="help-text">触发自动封禁所需的违规次数</div>
            </el-col>
            <el-col :span="12">
              <el-input :value="formattedBanFor" readonly placeholder="封禁时长">
                <template #prepend>封禁时长</template>
              </el-input>
              <div class="help-text">封禁时长在服务启动时通过参数设置,不可热更新</div>
            </el-col>
          </el-row>
        </el-form-item>
      </el-form>
    </el-card>
  </div>
</template>

<script lang="ts" setup>
import { ref, watch, computed, onMounted, onUnmounted } from 'vue'
import { ElMessage } from 'element-plus'
import { useWafStore } from '@/stores/waf'

const wafStore = useWafStore()

const configLoaded = ref(false)
const saving = ref(false)

const formData = ref({
  mode: 'block',
  maxBody: 1048576,
  rps: 20,
  burst: 40,
  trustXFF: false,
  banStrikes: 5,
})

// Read-only display of the server-side ban duration (Go duration string).
const formattedBanFor = computed(() => {
  const s = wafStore.config.banFor
  if (!s || s === '0s' || s === '0') return '永久封禁'
  // Handle Go-style duration strings like "10m0s", "1h30m", "90s", "24h".
  let secs = 0
  const re = /(\d+)([smh])/g
  let match
  while ((match = re.exec(s)) !== null) {
    const n = Number(match[1])
    switch (match[2]) {
      case 'h':
        secs += n * 3600
        break
      case 'm':
        secs += n * 60
        break
      case 's':
        secs += n
        break
    }
  }
  if (secs <= 0) return s
  const h = Math.floor(secs / 3600)
  const m = Math.floor((secs % 3600) / 60)
  const sc = Math.floor(secs % 60)
  const parts: string[] = []
  if (h) parts.push(`${h} 小时`)
  if (m) parts.push(`${m} 分钟`)
  if (sc && !h && !m) parts.push(`${sc} 秒`)
  return parts.length ? parts.join(' ') : s
})

// Populate the form from the server config. Using a watcher with `immediate`
// keeps the form in sync if the store value is refreshed elsewhere.
const stopWatch = watch(
  () => wafStore.config,
  (cfg) => {
    formData.value = {
      mode: cfg.mode,
      maxBody: cfg.maxBody,
      rps: cfg.rps,
      burst: cfg.burst,
      trustXFF: cfg.trustXFF,
      banStrikes: cfg.banStrikes,
    }
    configLoaded.value = true
  },
  { immediate: true, deep: true },
)

onMounted(() => {
  wafStore.loadConfig()
})

onUnmounted(() => stopWatch())

const setMaxBody = (bytes: number) => {
  formData.value.maxBody = bytes
}

const saveConfig = async () => {
  saving.value = true
  try {
    await wafStore.updateConfig({
      mode: formData.value.mode,
      maxBody: formData.value.maxBody,
      rps: formData.value.rps,
      burst: formData.value.burst,
      trustXFF: formData.value.trustXFF,
      banStrikes: formData.value.banStrikes,
    })
    ElMessage.success('配置已保存')
  } catch (error) {
    ElMessage.error('保存失败')
  } finally {
    saving.value = false
  }
}
</script>
