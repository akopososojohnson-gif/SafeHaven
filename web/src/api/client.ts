const API_BASE = '/api/v1'

export interface RegisterRequest {
  email: string
  zkp_public_key: string
  argon2_salt: string
  argon2_memory: number
  argon2_iterations: number
  argon2_parallelism: number
  vault_key_wrap: string
}

export interface ChallengeResponse {
  challenge_id: string
  challenge: string
  zkp_params: { group: string; generator: string }
}

export interface VerifyRequest {
  challenge_id: string
  proof_t: string
  proof_s: string
}

export interface VerifyResponse {
  access_token: string
  refresh_token: string
  token_type: string
  expires_in: number
}

export interface VaultItemRequest {
  item_type: string
  blob: string
  blob_size: number
  name_hash?: string
  parent_id?: string
  tags?: string[]
  favorite?: boolean
}

export interface VaultItemResponse {
  id: string
  blob_id: string
  version: number
  created_at: string
  updated_at?: string
}

export interface SyncResponse {
  items: VaultItemSync[]
  deleted_ids: string[]
  server_timestamp: string
  has_more: boolean
}

export interface VaultItemSync {
  id: string
  blob_id: string
  item_type: string
  version: number
  updated_at: string
  deleted: boolean
  name_hash?: string
  parent_id?: string
  tags: string[]
  favorite: boolean
}

class ApiClient {
  private token: string | null = null

  setToken(token: string | null) {
    this.token = token
  }

  private headers(): HeadersInit {
    const h: HeadersInit = { 'Content-Type': 'application/json' }
    if (this.token) h['Authorization'] = `Bearer ${this.token}`
    return h
  }

  private async fetch(path: string, init?: RequestInit): Promise<Response> {
    const res = await fetch(`${API_BASE}${path}`, {
      ...init,
      headers: { ...this.headers(), ...(init?.headers || {}) },
    })
    return res
  }

  async register(req: RegisterRequest) {
    const res = await this.fetch('/auth/register', { method: 'POST', body: JSON.stringify(req) })
    if (!res.ok) throw new Error(await res.text())
    return res.json()
  }

  async challenge(email: string): Promise<ChallengeResponse> {
    const res = await this.fetch('/auth/challenge', { method: 'POST', body: JSON.stringify({ email }) })
    if (!res.ok) throw new Error(await res.text())
    return res.json()
  }

  async verify(req: VerifyRequest): Promise<VerifyResponse> {
    const res = await this.fetch('/auth/verify', { method: 'POST', body: JSON.stringify(req) })
    if (!res.ok) throw new Error(await res.text())
    return res.json()
  }

  async logout() {
    const res = await this.fetch('/auth/logout', { method: 'POST' })
    if (!res.ok) throw new Error(await res.text())
  }

  async sync(since?: string, includeDeleted?: boolean): Promise<SyncResponse> {
    const params = new URLSearchParams()
    if (since) params.set('since', since)
    if (includeDeleted) params.set('include_deleted', 'true')
    const res = await this.fetch(`/vault/sync?${params.toString()}`)
    if (!res.ok) throw new Error(await res.text())
    const data = await res.json()
    if (!data.items) data.items = []
    if (!data.deleted_ids) data.deleted_ids = []
    return data
  }

  async createVaultItem(req: VaultItemRequest): Promise<VaultItemResponse> {
    const res = await this.fetch('/vault/items', { method: 'POST', body: JSON.stringify(req) })
    if (!res.ok) throw new Error(await res.text())
    return res.json()
  }

  async getBlob(blobId: string): Promise<ArrayBuffer> {
    const res = await this.fetch(`/vault/blobs/${blobId}`)
    if (!res.ok) throw new Error(await res.text())
    return res.arrayBuffer()
  }

  async deleteVaultItem(id: string) {
    const res = await this.fetch(`/vault/items/${id}`, { method: 'DELETE' })
    if (!res.ok) throw new Error(await res.text())
  }

  async me() {
    const res = await this.fetch('/user/me')
    if (!res.ok) throw new Error(await res.text())
    return res.json()
  }
}

export const api = new ApiClient()
