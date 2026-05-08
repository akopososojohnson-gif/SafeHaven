import { create } from 'zustand'
import { api } from '../api/client'
import type { VaultItemSync } from '../api/client'

interface VaultState {
  accessToken: string | null
  refreshToken: string | null
  user: { id: string; email: string } | null
  items: VaultItemSync[]
  lastSync: string | null
  salt: Uint8Array | null
  masterKey: Uint8Array | null
  zkpScalar: Uint8Array | null
  kek: Uint8Array | null
  vaultKey: Uint8Array | null

  setTokens: (access: string, refresh: string) => void
  clearTokens: () => void
  setUser: (user: { id: string; email: string }) => void
  setItems: (items: VaultItemSync[]) => void
  addItem: (item: VaultItemSync) => void
  removeItem: (id: string) => void
  setCryptoKeys: (salt: Uint8Array, masterKey: Uint8Array, zkpScalar: Uint8Array, kek: Uint8Array, vaultKey: Uint8Array) => void
  clearCryptoKeys: () => void
  logout: () => Promise<void>
}

export const useVaultStore = create<VaultState>((set, get) => ({
  accessToken: localStorage.getItem('sh_access_token'),
  refreshToken: localStorage.getItem('sh_refresh_token'),
  user: null,
  items: [],
  lastSync: null,
  salt: null,
  masterKey: null,
  zkpScalar: null,
  kek: null,
  vaultKey: null,

  setTokens(access, refresh) {
    localStorage.setItem('sh_access_token', access)
    localStorage.setItem('sh_refresh_token', refresh)
    api.setToken(access)
    set({ accessToken: access, refreshToken: refresh })
  },

  clearTokens() {
    localStorage.removeItem('sh_access_token')
    localStorage.removeItem('sh_refresh_token')
    localStorage.removeItem('sh_email')
    localStorage.removeItem('sh_salt')
    api.setToken(null)
    set({
      accessToken: null,
      refreshToken: null,
      user: null,
      items: [],
      salt: null,
      masterKey: null,
      zkpScalar: null,
      kek: null,
      vaultKey: null,
    })
  },

  setUser(user) {
    localStorage.setItem('sh_email', user.email)
    set({ user })
  },

  setItems(items) {
    set({ items })
  },

  addItem(item) {
    set((s) => ({ items: [item, ...s.items] }))
  },

  removeItem(id) {
    set((s) => ({ items: s.items.filter((i) => i.id !== id) }))
  },

  setCryptoKeys(salt, masterKey, zkpScalar, kek, vaultKey) {
    localStorage.setItem('sh_salt', Array.from(salt).join(','))
    set({ salt, masterKey, zkpScalar, kek, vaultKey })
  },

  clearCryptoKeys() {
    set({ salt: null, masterKey: null, zkpScalar: null, kek: null, vaultKey: null })
  },

  async logout() {
    try {
      await api.logout()
    } catch {
      // ignore
    }
    get().clearTokens()
  },
}))

// Hydrate API client token on load
const stored = localStorage.getItem('sh_access_token')
if (stored) api.setToken(stored)

// Hydrate salt from localStorage if present
const storedSalt = localStorage.getItem('sh_salt')
if (storedSalt) {
  const bytes = new Uint8Array(storedSalt.split(',').map(Number))
  useVaultStore.setState({ salt: bytes })
}
