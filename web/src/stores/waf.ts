import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { api } from '@/api'

export interface Rule {
  id: string
  category: string
  where: string
  pattern: string
  keywords?: string[]
}

export interface Config {
  mode: string
  maxBody: number
  rps: number
  burst: number
  trustXFF: boolean
  banStrikes: number
  banFor: string
  allow: string[]
  deny: string[]
}

export interface Metrics {
  requests_total: number
  rule_matched: number
  blocked: number
  rate_limited: number
  rules_loaded: number
  mode: string
  allow_count: number
  deny_count: number
}

export const useWafStore = defineStore('waf', () => {
  const rules = ref<Rule[]>([])
  const config = ref<Config>({
    mode: 'block',
    maxBody: 1048576,
    rps: 20,
    burst: 40,
    trustXFF: false,
    banStrikes: 5,
    banFor: '10m',
    allow: [],
    deny: [],
  })
  const metrics = ref<Metrics>({
    requests_total: 0,
    rule_matched: 0,
    blocked: 0,
    rate_limited: 0,
    rules_loaded: 0,
    mode: 'block',
    allow_count: 0,
    deny_count: 0,
  })
  const allowList = ref<string[]>([])
  const denyList = ref<string[]>([])

  // Load rules from API
  const loadRules = async () => {
    try {
      const response = await api.getRules()
      rules.value = response.data.rules
    } catch (error) {
      console.error('Failed to load rules:', error)
    }
  }

  // Create rules
  const createRules = async (newRules: Partial<Rule>[]) => {
    try {
      const response = await api.createRules(newRules)
      await loadRules()
      return response.data
    } catch (error) {
      console.error('Failed to create rules:', error)
      throw error
    }
  }

  // Update rule
  const updateRule = async (id: string, rule: Partial<Rule>) => {
    try {
      const response = await api.updateRule(id, rule)
      await loadRules()
      return response.data
    } catch (error) {
      console.error('Failed to update rule:', error)
      throw error
    }
  }

  // Delete rule
  const deleteRule = async (id: string) => {
    try {
      const response = await api.deleteRule(id)
      await loadRules()
      return response.data
    } catch (error) {
      console.error('Failed to delete rule:', error)
      throw error
    }
  }

  // Load config
  const loadConfig = async () => {
    try {
      const response = await api.getConfig()
      config.value = response.data
    } catch (error) {
      console.error('Failed to load config:', error)
    }
  }

  // Update config
  const updateConfig = async (newConfig: Partial<Config>) => {
    try {
      const response = await api.updateConfig(newConfig)
      await loadConfig()
      return response.data
    } catch (error) {
      console.error('Failed to update config:', error)
      throw error
    }
  }

  // Load metrics
  const loadMetrics = async () => {
    try {
      const response = await api.getMetrics()
      metrics.value = response.data
    } catch (error) {
      console.error('Failed to load metrics:', error)
    }
  }

  // Load allow list
  const loadAllowList = async () => {
    try {
      const response = await api.getAllowList()
      allowList.value = response.data.ips
    } catch (error) {
      console.error('Failed to load allow list:', error)
    }
  }

  // Add to allow list
  const addToAllowList = async (ips: string[]) => {
    try {
      const response = await api.addToAllowList(ips)
      await loadAllowList()
      return response.data
    } catch (error) {
      console.error('Failed to add to allow list:', error)
      throw error
    }
  }

  // Remove from allow list
  const removeFromAllowList = async (ips: string[]) => {
    try {
      const response = await api.removeFromAllowList(ips)
      await loadAllowList()
      return response.data
    } catch (error) {
      console.error('Failed to remove from allow list:', error)
      throw error
    }
  }

  // Load deny list
  const loadDenyList = async () => {
    try {
      const response = await api.getDenyList()
      denyList.value = response.data.ips
    } catch (error) {
      console.error('Failed to load deny list:', error)
    }
  }

  // Add to deny list
  const addToDenyList = async (ips: string[]) => {
    try {
      const response = await api.addToDenyList(ips)
      await loadDenyList()
      return response.data
    } catch (error) {
      console.error('Failed to add to deny list:', error)
      throw error
    }
  }

  // Remove from deny list
  const removeFromDenyList = async (ips: string[]) => {
    try {
      const response = await api.removeFromDenyList(ips)
      await loadDenyList()
      return response.data
    } catch (error) {
      console.error('Failed to remove from deny list:', error)
      throw error
    }
  }

  // Get stats by category
  const getStatsByCategory = async () => {
    // This would need implementation in the backend
    return []
  }

  return {
    rules,
    config,
    metrics,
    allowList,
    denyList,
    loadRules,
    createRules,
    updateRule,
    deleteRule,
    loadConfig,
    updateConfig,
    loadMetrics,
    loadAllowList,
    addToAllowList,
    removeFromAllowList,
    loadDenyList,
    addToDenyList,
    removeFromDenyList,
  }
})