<template>
  <el-config-provider :locale="zhCn">
    <router-view />
  </el-config-provider>
</template>

<script lang="ts" setup>
import zhCn from 'element-plus/es/locale/lang/zh-cn'
</script>

<style>
/* ===== Dark theme overrides for Element Plus ===== */
.dark-theme {
  /* Element Plus dark theme */
  --el-color-primary: #409eff;
  --el-color-primary-darken: #3378c8;
  --el-color-warning: #e6a23c;
  --el-color-danger: #ff4d4f;
  --el-color-success: #67c23a;
  
  /* Form inputs */
  --el-input-border-color: #444a53;
  --el-input-bg-color: #1d1f21;
  --el-input-color: #e4e7ed;
  --el-input-placeholder-color: #7a7a7a;
  
  /* Table */
  --el-table-row-bg-color: #1d1f21;
  --el-table-row-hover-bg-color: rgba(64, 159, 255, 0.15);
  
  /* Menu */
  --el-menu-bg-color: #1a1d23;
  --el-menu-text-color: #a0a0a0;
  --el-menu-active-bg-color: rgba(64, 159, 255, 0.15);
  
  /* Card */
  --el-card-bg-color: #262a2e;
  --el-card-border-color: #444a53;
  
  /* Header */
  --el-header-bg-color: #262a2e;
  --el-header-border-color: #444a53;
  
  /* Side menu */
  --el-aside-bg-color: #1a1d23;
}
</style>