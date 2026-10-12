import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { api } from '@/api'

// --- Types ---

export type UserRole = 'admin' | 'user' | 'auditor'

export interface BastionUser {
  id?: number
  username: string
  public_key: string
  role: UserRole
  assets: string[]
  comment: string
  created_at: string
}

export interface BastionUserCreate {
  username: string
  password: string
  public_key?: string
  role: UserRole
  assets?: string[]
  comment?: string
}

export interface BastionUserUpdate {
  password?: string
  public_key?: string
  role?: UserRole
  assets?: string[]
  comment?: string
}

export interface BastionAsset {
  id: string
  name: string
  hostname: string
  port: number
  username: string
  private_key_file?: string
  comment: string
  created_at: string
}

export interface BastionAssetCreate {
  name: string
  hostname: string
  port?: number
  username?: string
  password?: string
  private_key_file?: string
  private_key?: string
  comment?: string
}

export interface BastionAssetUpdate {
  name?: string
  hostname?: string
  port?: number
  username?: string
  password?: string
  private_key_file?: string
  private_key?: string
  comment?: string
}

export interface BastionSession {
  id: string
  username: string
  asset_id: string
  asset_name: string
  start_time: string
  end_time: string
  duration: string
  status: 'active' | 'closed'
  recording_path?: string
}

export interface BastionAuditEvent {
  timestamp: string
  username: string
  session_id: string
  asset_id: string
  asset_name: string
  action: string
  command?: string
  working_dir?: string
  exit_code?: number
  blocked: boolean
  rule_id?: string
  raw_input?: string
  client_ip?: string
}

export interface BastionBannedCommand {
  id: string
  pattern: string
  reason: string
  enabled: boolean
}

export interface BastionConfigResponse {
  ssh_listen_addr: string
  api_listen_addr: string
  host_key_path: string
  recording_dir: string
  audit_log_path: string
  default_user: string
  default_port: number
  max_sessions: number
  banner_msg: string
}

export interface BastionHealthResponse {
  status: string
  ssh_listen: string
  active_sessions: number
  uptime?: string
  user_store?: string
}

// --- Store ---

export const useBastionStore = defineStore('bastion', () => {
  // State
  const users = ref<BastionUser[]>([])
  const assets = ref<BastionAsset[]>([])
  const sessions = ref<BastionSession[]>([])
  const auditEvents = ref<BastionAuditEvent[]>([])
  const bannedCommands = ref<BastionBannedCommand[]>([])
  const config = ref<Partial<BastionConfigResponse>>({})
  const health = ref<Partial<BastionHealthResponse>>({ status: 'unknown' })
  const loading = ref(false)

  // 用户列表的数据来源,由后端在 GET /api/bastion/users 的响应里返回,
  // 例如 { store: 'mysql(user1)', table: 'user1' }。用于页面展示「数据来源」。
  const userStore = ref('')
  const userTable = ref('')
  // 加载用户列表失败时的错误信息(例如数据库连接超时),供页面提示。
  const usersError = ref('')

  // Whether the bastion module is enabled on the backend.
  // null = unknown (health check not yet completed), true/false = known.
  const bastionEnabled = ref<boolean | null>(null)
  const bastionError = ref('')

  // Computed
  const activeSessions = computed(() => sessions.value.filter(s => s.status === 'active'))
  const closedSessions = computed(() => sessions.value.filter(s => s.status === 'closed'))
  const totalSessions = computed(() => sessions.value.length)
  const userCount = computed(() => users.value.length)
  const assetCount = computed(() => assets.value.length)
  const adminCount = computed(() => users.value.filter(u => u.role === 'admin').length)
  const normalUserCount = computed(() => users.value.filter(u => u.role === 'user').length)
  const auditorCount = computed(() => users.value.filter(u => u.role === 'auditor').length)

  /**
   * Detect whether an error is a 503 Service Unavailable response from the
   * backend (meaning the SSH bastion module is not enabled). When it is,
   * update the store-level state so the rest of the app can react.
   *
   * Returns true if this was a "bastion not enabled" error (already handled),
   * false otherwise (caller should log / rethrow).
   */
  const isBastionDisabled = (error: any): boolean => {
    if (error?.response?.status === 503) {
      const msg =
        error.response?.data?.error ||
        'Bastion (SSH jump server) is not enabled'
      bastionEnabled.value = false
      bastionError.value = msg
      return true
    }
    return false
  }

  // Guard helper for mutation operations.
  const requireBastionEnabled = (): void => {
    if (bastionEnabled.value === false) {
      throw new Error(bastionError.value || 'Bastion is not enabled')
    }
  }

  // Unwrap axios responses. Callers type the API as the JSON body, but
  // axios actually returns AxiosResponse, so the payload lives on `.data`.
  const payload = (response: any): any => response?.data ?? response

  const markEnabled = () => {
    bastionEnabled.value = true
    bastionError.value = ''
  }

  // --- Users ---

  const loadUsers = async () => {
    try {
      loading.value = true
      usersError.value = ''
      const body = payload(await api.bastionGetUsers())
      users.value = Array.isArray(body?.users) ? body.users : []
      if (typeof body?.store === 'string') userStore.value = body.store
      if (typeof body?.table === 'string') userTable.value = body.table
      markEnabled()
    } catch (error: any) {
      if (!isBastionDisabled(error)) {
        usersError.value =
          error?.response?.data?.error ||
          error?.message ||
          '加载用户列表失败'
        console.error('Failed to load users:', error)
      }
    } finally {
      loading.value = false
    }
  }

  const createUser = async (user: BastionUserCreate) => {
    requireBastionEnabled()
    try {
      await api.bastionCreateUser(user)
      await loadUsers()
    } catch (error) {
      console.error('Failed to create user:', error)
      throw error
    }
  }

  const updateUser = async (username: string, user: BastionUserUpdate) => {
    requireBastionEnabled()
    try {
      await api.bastionUpdateUser(username, user)
      await loadUsers()
    } catch (error) {
      console.error('Failed to update user:', error)
      throw error
    }
  }

  const deleteUser = async (username: string) => {
    requireBastionEnabled()
    try {
      await api.bastionDeleteUser(username)
      await loadUsers()
    } catch (error) {
      console.error('Failed to delete user:', error)
      throw error
    }
  }

  // --- Assets ---

  const loadAssets = async () => {
    try {
      loading.value = true
      const body = payload(await api.bastionGetAssets())
      assets.value = Array.isArray(body?.assets) ? body.assets : []
      markEnabled()
    } catch (error) {
      if (!isBastionDisabled(error)) {
        console.error('Failed to load assets:', error)
      }
    } finally {
      loading.value = false
    }
  }

  const createAsset = async (asset: BastionAssetCreate) => {
    requireBastionEnabled()
    try {
      await api.bastionCreateAsset(asset)
      await loadAssets()
    } catch (error) {
      console.error('Failed to create asset:', error)
      throw error
    }
  }

  const updateAsset = async (id: string, asset: BastionAssetUpdate) => {
    requireBastionEnabled()
    try {
      await api.bastionUpdateAsset(id, asset)
      await loadAssets()
    } catch (error) {
      console.error('Failed to update asset:', error)
      throw error
    }
  }

  const deleteAsset = async (id: string) => {
    requireBastionEnabled()
    try {
      await api.bastionDeleteAsset(id)
      await loadAssets()
    } catch (error) {
      console.error('Failed to delete asset:', error)
      throw error
    }
  }

  // --- Sessions ---

  const loadSessions = async () => {
    try {
      loading.value = true
      const body = payload(await api.bastionGetSessions())
      sessions.value = Array.isArray(body?.sessions) ? body.sessions : []
      markEnabled()
    } catch (error) {
      if (!isBastionDisabled(error)) {
        console.error('Failed to load sessions:', error)
      }
    } finally {
      loading.value = false
    }
  }

  const downloadRecording = async (sessionId: string) => {
    requireBastionEnabled()
    try {
      const response = await api.bastionGetRecording(sessionId)
      // Create a download link
      const url = URL.createObjectURL(response)
      const a = document.createElement('a')
      a.href = url
      a.download = `${sessionId}.cast`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
    } catch (error) {
      console.error('Failed to download recording:', error)
      throw error
    }
  }

  // --- Audit ---

  const loadAudit = async (params?: { user?: string; session?: string }) => {
    try {
      loading.value = true
      const body = payload(await api.bastionGetAudit(params))
      auditEvents.value = Array.isArray(body?.events) ? body.events : []
      markEnabled()
    } catch (error) {
      if (!isBastionDisabled(error)) {
        console.error('Failed to load audit events:', error)
      }
    } finally {
      loading.value = false
    }
  }

  // --- Banned Commands ---

  const loadBannedCommands = async () => {
    try {
      loading.value = true
      const body = payload(await api.bastionGetBanned())
      bannedCommands.value = Array.isArray(body?.rules) ? body.rules : []
      markEnabled()
    } catch (error) {
      if (!isBastionDisabled(error)) {
        console.error('Failed to load banned commands:', error)
      }
    } finally {
      loading.value = false
    }
  }

  const addBannedCommand = async (cmd: Omit<BastionBannedCommand, 'id'>) => {
    requireBastionEnabled()
    try {
      await api.bastionAddBanned(cmd as BastionBannedCommand)
      await loadBannedCommands()
    } catch (error) {
      console.error('Failed to add banned command:', error)
      throw error
    }
  }

  // --- Config ---

  const loadConfig = async () => {
    try {
      config.value = payload(await api.bastionGetConfig())
      markEnabled()
    } catch (error) {
      if (!isBastionDisabled(error)) {
        console.error('Failed to load config:', error)
      }
    }
  }

  const updateConfig = async (newConfig: Partial<BastionConfigResponse>) => {
    requireBastionEnabled()
    try {
      await api.bastionUpdateConfig(newConfig)
      await loadConfig()
    } catch (error) {
      console.error('Failed to update config:', error)
      throw error
    }
  }

  // --- Health ---

  const loadHealth = async () => {
    try {
      health.value = payload(await api.bastionHealth())
      markEnabled()
    } catch (error) {
      if (isBastionDisabled(error)) {
        // 503 is expected when the bastion module is not enabled — update state, no console noise.
        health.value = { status: 'disabled' }
      } else {
        console.error('Failed to load health:', error)
        health.value = { status: 'error' }
      }
    }
  }

  // --- Bulk load ---

  const loadAll = async () => {
    await loadHealth()
    if (bastionEnabled.value === false) return
    await loadUsers()
    await loadAssets()
    await loadSessions()
    await loadBannedCommands()
    await loadConfig()
  }

  return {
    // State
    users,
    assets,
    sessions,
    auditEvents,
    bannedCommands,
    config,
    health,
    loading,
    bastionEnabled,
    bastionError,
    userStore,
    userTable,
    usersError,

    // Computed
    activeSessions,
    closedSessions,
    totalSessions,
    userCount,
    assetCount,
    adminCount,
    normalUserCount,
    auditorCount,

    // Users
    loadUsers,
    createUser,
    updateUser,
    deleteUser,

    // Assets
    loadAssets,
    createAsset,
    updateAsset,
    deleteAsset,

    // Sessions
    loadSessions,
    downloadRecording,

    // Audit
    loadAudit,

    // Banned Commands
    loadBannedCommands,
    addBannedCommand,

    // Config
    loadConfig,
    updateConfig,

    // Health
    loadHealth,

    // Bulk
    loadAll,
  }
})
