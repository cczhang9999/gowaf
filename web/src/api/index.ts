import axios from 'axios'
import type { Rule, Config, Metrics } from '@/stores/waf'
import type {
  BastionUser,
  BastionUserCreate,
  BastionUserUpdate,
  BastionAsset,
  BastionAssetCreate,
  BastionAssetUpdate,
  BastionSession,
  BastionAuditEvent,
  BastionBannedCommand,
  BastionConfigResponse,
  BastionHealthResponse,
} from '@/stores/bastion'

// Create axios instance
const instance = axios.create({
  baseURL: '/api',
  timeout: 10000,
})

// --- API token handling ---------------------------------------------------
// The management API can require `Authorization: Bearer <token>`. The token is
// kept in localStorage so it survives reloads. When the backend rejects a
// request for a missing/invalid token we prompt once and retry, instead of
// silently failing every page.
const TOKEN_KEY = 'gowaf_api_token'

export function getApiToken(): string {
  return localStorage.getItem(TOKEN_KEY) || ''
}

export function setApiToken(token: string): void {
  if (token) localStorage.setItem(TOKEN_KEY, token)
  else localStorage.removeItem(TOKEN_KEY)
}

let prompting = false
// Tracks requests already retried once, so a bad token cannot cause a loop.
const retried = new WeakSet<object>()

instance.interceptors.request.use((config) => {
  const token = getApiToken()
  if (token) {
    config.headers = config.headers ?? {}
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

instance.interceptors.response.use(
  (response) => response,
  async (error) => {
    const response = error?.response
    const status = response?.status
    const body = response?.data
    const isAuthError =
      status === 401 ||
      (status === 403 && typeof body?.error === 'string' && body.error.includes('API token'))

    const original = error?.config
    if (isAuthError && original && !retried.has(original) && !prompting) {
      prompting = true
      try {
        const entered = window.prompt(
          'This management API requires an authentication token.\n' +
            'Paste the token from config.yaml (security.api_auth.token):',
          getApiToken(),
        )
        if (entered !== null && entered.trim() !== '') {
          setApiToken(entered.trim())
          retried.add(original)
          return instance.request(original)
        }
      } finally {
        prompting = false
      }
    }
    return Promise.reject(error)
  },
)

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

  // --- Bastion (SSH) APIs ---
  // The base path is /api/bastion (mounted by the Go backend)
  bastionPrefix: '/bastion',

  // Users
  bastionGetUsers(): Promise<{
    users: BastionUser[]
    count: number
    store?: string
    table?: string
  }> {
    return instance.get(`${this.bastionPrefix}/users`)
  },

  bastionCreateUser(user: BastionUserCreate): Promise<SuccessResponse & { username: string }> {
    return instance.post(`${this.bastionPrefix}/users`, user)
  },

  bastionGetUser(id: string): Promise<{ data: BastionUser }> {
    return instance.get(`${this.bastionPrefix}/users/${id}`)
  },

  bastionUpdateUser(id: string, user: BastionUserUpdate): Promise<SuccessResponse> {
    return instance.put(`${this.bastionPrefix}/users/${id}`, user)
  },

  bastionDeleteUser(id: string): Promise<SuccessResponse> {
    return instance.delete(`${this.bastionPrefix}/users/${id}`)
  },

  // Assets
  bastionGetAssets(): Promise<{ assets: BastionAsset[]; count: number }> {
    return instance.get(`${this.bastionPrefix}/assets`)
  },

  bastionCreateAsset(asset: BastionAssetCreate): Promise<SuccessResponse & { id: string }> {
    return instance.post(`${this.bastionPrefix}/assets`, asset)
  },

  bastionGetAsset(id: string): Promise<{ data: BastionAsset }> {
    return instance.get(`${this.bastionPrefix}/assets/${id}`)
  },

  bastionUpdateAsset(id: string, asset: BastionAssetUpdate): Promise<SuccessResponse> {
    return instance.put(`${this.bastionPrefix}/assets/${id}`, asset)
  },

  bastionDeleteAsset(id: string): Promise<SuccessResponse> {
    return instance.delete(`${this.bastionPrefix}/assets/${id}`)
  },

  // Sessions
  bastionGetSessions(): Promise<{ sessions: BastionSession[]; count: number; active: number }> {
    return instance.get(`${this.bastionPrefix}/sessions`)
  },

  bastionGetRecording(sessionId: string): Promise<Blob> {
    return instance.get(`${this.bastionPrefix}/sessions/${sessionId}/recording`, {
      responseType: 'blob',
    })
  },

  // Audit
  bastionGetAudit(params?: { user?: string; session?: string }): Promise<{ events: BastionAuditEvent[]; count: number }> {
    return instance.get(`${this.bastionPrefix}/audit`, { params })
  },

  // Banned Commands
  bastionGetBanned(): Promise<{ rules: BastionBannedCommand[]; count: number }> {
    return instance.get(`${this.bastionPrefix}/banned`)
  },

  bastionAddBanned(cmd: BastionBannedCommand): Promise<SuccessResponse & { id: string }> {
    return instance.post(`${this.bastionPrefix}/banned`, cmd)
  },

  // Config
  bastionGetConfig(): Promise<{ data: BastionConfigResponse }> {
    return instance.get(`${this.bastionPrefix}/config`)
  },

  bastionUpdateConfig(config: Partial<BastionConfigResponse>): Promise<SuccessResponse> {
    return instance.put(`${this.bastionPrefix}/config`, config)
  },

  // Health
  bastionHealth(): Promise<BastionHealthResponse> {
    return instance.get(`${this.bastionPrefix}/healthz`)
  },
}