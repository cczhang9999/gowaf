import { createRouter, createWebHistory } from 'vue-router'
import Layout from '@/views/Layout.vue'

const routes = [
  {
    path: '/',
    component: Layout,
    children: [
      {
        path: '',
        name: 'Dashboard',
        component: () => import('@/views/Dashboard.vue'),
        meta: { title: '仪表盘' },
      },
      {
        path: 'rules',
        name: 'Rules',
        component: () => import('@/views/Rules.vue'),
        meta: { title: '规则管理' },
      },
      {
        path: 'config',
        name: 'Config',
        component: () => import('@/views/Config.vue'),
        meta: { title: '配置管理' },
      },
      {
        path: 'ips',
        name: 'IPs',
        component: () => import('@/views/IPs.vue'),
        meta: { title: 'IP 列表' },
      },
      {
        path: 'metrics',
        name: 'Metrics',
        component: () => import('@/views/Metrics.vue'),
        meta: { title: '监控' },
      },
      // --- Bastion Host (SSH) routes ---
      {
        path: 'bastion',
        name: 'BastionDashboard',
        component: () => import('@/views/bastion/BastionDashboard.vue'),
        meta: { title: '堰垒机概览', section: 'bastion' },
      },
      {
        path: 'assets',
        name: 'BastionAssets',
        component: () => import('@/views/bastion/Assets.vue'),
        meta: { title: '资产管理', section: 'bastion' },
      },
      {
        path: 'users',
        name: 'BastionUsers',
        component: () => import('@/views/bastion/Users.vue'),
        meta: { title: '用户管理', section: 'bastion' },
      },
      {
        path: 'sessions',
        name: 'BastionSessions',
        component: () => import('@/views/bastion/Sessions.vue'),
        meta: { title: '会话记录', section: 'bastion' },
      },
      {
        path: 'audit',
        name: 'BastionAudit',
        component: () => import('@/views/bastion/Audit.vue'),
        meta: { title: '命令审计', section: 'bastion' },
      },
      {
        path: 'banned',
        name: 'BastionBanned',
        component: () => import('@/views/bastion/BannedCommands.vue'),
        meta: { title: '禁止命令', section: 'bastion' },
      },
    ],
  },
]

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes,
})

export default router