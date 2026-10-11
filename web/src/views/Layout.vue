<template>
  <el-container style="height: 100vh">
    <el-aside width="220px" class="nav-aside">
      <div class="logo">
        <h3>GoWAF Admin</h3>
      </div>
      <el-menu
        :default-active="activeRoute"
        mode="vertical"
        @select="handleMenuClick"
        :collapse="collapsed"
      >
        <el-menu-item index="/" title="仪表盘">
          <template #icon><Grid /></template>
          <span>仪表盘</span>
        </el-menu-item>
        <el-menu-item index="/rules" title="规则管理">
          <template #icon><Document /></template>
          <span>规则管理</span>
        </el-menu-item>
        <el-menu-item index="/config" title="配置">
          <template #icon><Setting /></template>
          <span>配置</span>
        </el-menu-item>
        <el-menu-item index="/ips" title="IP 列表">
          <template #icon><Lock /></template>
          <span>IP 列表</span>
        </el-menu-item>
        <el-menu-item index="/metrics" title="监控">
          <template #icon><DataAnalysis /></template>
          <span>监控</span>
        </el-menu-item>

        <el-divider borderless class="section-divider" />
        <div class="menu-section-label">堰垒机</div>

        <el-menu-item index="/bastion" title="堰垒机概览">
          <template #icon><Connection /></template>
          <span>概览</span>
        </el-menu-item>
        <el-menu-item index="/assets" title="资产管理">
          <template #icon><Monitor /></template>
          <span>资产管理</span>
        </el-menu-item>
        <el-menu-item index="/users" title="用户管理">
          <template #icon><User /></template>
          <span>用户管理</span>
        </el-menu-item>
        <el-menu-item index="/sessions" title="会话记录">
          <template #icon><Clock /></template>
          <span>会话记录</span>
        </el-menu-item>
        <el-menu-item index="/audit" title="命令审计">
          <template #icon><Document /></template>
          <span>命令审计</span>
        </el-menu-item>
        <el-menu-item index="/banned" title="禁止命令">
          <template #icon><Warning /></template>
          <span>禁止命令</span>
        </el-menu-item>
      </el-menu>
    </el-aside>

    <el-container style="flex-direction: column; height: 100vh">
      <el-header class="page-header-bar" height="56">
        <div class="breadcrumb">
          <span
            v-for="(item, i) in breadcrumbItems"
            :key="item.path"
            class="breadcrumb-item"
            @click="i < breadcrumbItems.length - 1 && navigate(item)"
          >
            <span v-if="i > 0" class="breadcrumb-separator">/</span>
            {{ item.title }}
          </span>
        </div>
        <div class="header-actions">
          <el-link :href="docsUrl" target="_blank" title="帮助文档">
            <Help />
          </el-link>
          <div 
            class="theme-toggle" 
            :class="{ 'active': isDark }"
            @click="toggleTheme"
            title="切换主题"
          >
            <template v-if="!isDark">🌙</template>
            <template v-else>☀️</template>
          </div>
        </div>
      </el-header>

      <el-main class="main-content">
        <router-view />
      </el-main>
    </el-container>
  </el-container>
</template>

<script lang="ts" setup>
import { ref, watch, computed, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useWafStore } from '@/stores/waf'
import { useBastionStore } from '@/stores/bastion'
import { useThemeStore } from '@/stores/theme'
import {
  Grid,
  Document,
  Setting,
  Lock,
  DataAnalysis,
  Connection,
  Monitor,
  User,
  Clock,
  Warning,
  Help,
} from '@element-plus/icons-vue'

const route = useRoute()
const router = useRouter()
const wafStore = useWafStore()
const bastionStore = useBastionStore()
const themeStore = useThemeStore()

const collapsed = ref(false)
const activeRoute = ref(route.path)

watch(
  () => route.path,
  (newPath) => {
    activeRoute.value = newPath
  },
)

// Breadcrumb built from the matched route records (uses meta.title).
const breadcrumbItems = computed(() =>
  route.matched
    .filter((r) => r.meta && r.meta.title)
    .map((r) => ({
      title: (r.meta.title as string) ?? '',
      path: r.path,
    })),
)

const navigate = (item: { path: string; title: string }) => {
  router.push(item.path)
}

// Keep the document title in sync with the active route.
watch(
  () => route.meta.title,
  (title) => {
    document.title = title ? `GoWAF - ${title}` : 'GoWAF Admin'
  },
  { immediate: true },
)

const docsUrl = 'https://github.com/example/gowaf'

const handleMenuClick = (index: string) => {
  router.push(index)
}

// Theme toggle
const isDark = computed({
  get: () => themeStore.isDark,
  set: (value) => themeStore.setTheme(value),
})

const toggleTheme = () => {
  themeStore.toggleTheme()
}

// Load initial data once on app boot.
onMounted(() => {
  // Load theme from storage
  themeStore.loadTheme()
  
  wafStore.loadMetrics()
  wafStore.loadRules()
  wafStore.loadConfig()
  wafStore.loadAllowList()
  wafStore.loadDenyList()

  // Load bastion data if bastion routes are accessible.
  bastionStore.loadHealth()
})
</script>

<style scoped>
.nav-aside {
  background-color: var(--background-sidebar);
}

.logo h3 {
  font-weight: normal;
  color: var(--sidebar-brand-text);
  padding: 15px;
  margin: 0;
}

.page-header-bar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  background-color: var(--background-header);
  border-bottom: 1px solid var(--border-color);
  padding: 0 20px;
  box-shadow: var(--shadow-header);
}

.section-divider {
  background-color: transparent;
}

.menu-section-label {
  padding: 8px 14px 4px;
  font-size: 11px;
  color: var(--sidebar-text-muted);
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.breadcrumb {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 13px;
  color: var(--text-disabled);
}

.breadcrumb-item {
  color: var(--text-disabled);
  cursor: pointer;
}

.breadcrumb-item:last-child {
  color: var(--text-primary);
  font-weight: 600;
  cursor: default;
}

.breadcrumb-separator {
  color: var(--border-color);
}

.main-content {
  background-color: var(--background-primary);
}

.header-actions {
  display: flex;
  align-items: center;
  gap: 12px;
}

/* ===== Theme toggle button ===== */
.theme-toggle {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 32px;
  height: 32px;
  border-radius: 4px;
  cursor: pointer;
  transition: all 0.3s;
  color: var(--text-secondary);
}

.theme-toggle:hover {
  background-color: var(--border-color);
  transform: scale(1.05);
}

.theme-toggle.active {
  color: #409eff;
}
</style>