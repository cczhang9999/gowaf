import axios from 'axios'
import type { Rule, Config, Metrics } from '@/stores/waf'

// Create axios instance
const instance = axios.create({
  baseURL: '/api',
  timeout: 10000,
})

// API responses
interface RulesResponse {
  rules: Rule[]
}

interface IPListResponse {
  ips: string[]
}

interface SuccessResponse {
  success: boolean
  count?: number
}

export const api = {
  // Rules APIs
  getRules(): Promise<RulesResponse> {
    return instance.get('/rules')
  },

  createRules(rules: Partial<Rule>[]): Promise<SuccessResponse> {
    return instance.post('/rules', rules)
  },

  getRule(id: string): Promise<{ data: Rule }> {
    return instance.get(`/rules/${id}`)
  },

  updateRule(id: string, rule: Partial<Rule>): Promise<SuccessResponse> {
    return instance.put(`/rules/${id}`, rule)
  },

  deleteRule(id: string): Promise<SuccessResponse> {
    return instance.delete(`/rules/${id}`)
  },

  // Config APIs
  getConfig(): Promise<{ data: Config }> {
    return instance.get('/config')
  },

  updateConfig(config: Partial<Config>): Promise<SuccessResponse> {
    return instance.put('/config', config)
  },

  // Allow List APIs
  getAllowList(): Promise<IPListResponse> {
    return instance.get('/allow')
  },

  addToAllowList(ips: string[]): Promise<SuccessResponse> {
    return instance.post('/allow', { ips })
  },

  removeFromAllowList(ips: string[]): Promise<SuccessResponse> {
    return instance.delete('/allow', { data: { ips } })
  },

  // Deny List APIs
  getDenyList(): Promise<IPListResponse> {
    return instance.get('/deny')
  },

  addToDenyList(ips: string[]): Promise<SuccessResponse> {
    return instance.post('/deny', { ips })
  },

  removeFromDenyList(ips: string[]): Promise<SuccessResponse> {
    return instance.delete('/deny', { data: { ips } })
  },

  // Metrics APIs
  getMetrics(): Promise<Metrics> {
    return instance.get('/metrics')
  },

  // Health check
  healthCheck(): Promise<void> {
    return instance.get('/healthz').then(() => {})
  },
}