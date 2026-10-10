<template>
  <el-container style="height: 100vh">
    <el-aside width="200px" style="background-color: #2c3e50">
      <div class="logo">
        <h3 style="color: white; padding: 15px; margin: 0;">GoWAF Admin</h3>
      </div>
      <el-menu
        :default-active="activeRoute"
        mode="vertical"
        @select="handleMenuClick"
        :collapsible="false"
        style="background-color: #2c3e50"
      >
        <el-menu-item index="/" title="仪表盘">
          <template #icon>
            <Grid />
          </template>
          <span>仪表盘</span>
        </el-menu-item>
        <el-menu-item index="/rules" title="规则管理">
          <template #icon>
            <Document />
          </template>
          <span>规则管理</span>
        </el-menu-item>
        <el-menu-item index="/config" title="配置">
          <template #icon>
            <Setting />
          </template>
          <span>配置</span>
        </el-menu-item>
        <el-menu-item index="/ips" title="IP 列表">
          <template #icon>
            <Lock />
          </template>
          <span>IP 列表</span>
        </el-menu-item>
        <el-menu-item index="/metrics" title="监控">
          <template #icon>
            <DataAnalysis />
          </template>
          <span>监控</span>
        </el-menu-item>
      </el-menu>
    </el-aside>
    <el-main style="background-color: #f5f7fa">
      <router-view />
    </el-main>
  </el-container>
</template>

<script lang="ts" setup>
import { ref, watch, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useWafStore } from '@/stores/waf'
import { Grid, Document, Setting, Lock, DataAnalysis } from '@element-plus/icons-vue'

const route = useRoute()
const router = useRouter()
const wafStore = useWafStore()

const activeRoute = ref(route.path)

watch(
  () => route.path,
  (newPath) => {
    activeRoute.value = newPath
  },
)

const handleMenuClick = (index: string) => {
  router.push(index)
}

// Load initial data
onMounted(() => {
  wafStore.loadMetrics()
  wafStore.loadRules()
  wafStore.loadConfig()
  wafStore.loadAllowList()
  wafStore.loadDenyList()
})
</script>

<style scoped>
.logo h3 {
  font-weight: normal;
}
</style>