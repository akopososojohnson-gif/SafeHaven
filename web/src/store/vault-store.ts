import { create } from 'zustand'
import { api } from '../api/client'
import type { VaultItemSync } from '../api/client'

interface VaultState {
  accessToken: string | null
  refreshToken: string | null
  user: { id: string; email: string } | null
  items: VaultItemSync[]
  lastSync: string | null
  setTokens: (access: string, refresh: string) => void
  clearTokens: () => void
  setUser: (user: { id: string; email: string }) => void
  setItems: (items: VaultItemSync[]) => void
  addItem: (item: VaultItemSync) => void
  removeItem: (id: string) => void
  logout: () => Promise<void>
}

export const useVaultStore = create<VaultState>((set, get) => ({
  accessToken: localStorage.getItem('sh_access_token'),
  refreshToken: localStorage.getItem('sh_refresh_token'),
  user: null,
  items: [],
  lastSync: null,

  setTokens(access, refresh) {
    localStorage.setItem('sh_access_token', access)
    localStorage.setItem('sh_refresh_token', refresh)
    api.setToken(access)
    set({ accessToken: access, refreshToken: refresh })
  },

  clearTokens() {
    localStorage.removeItem('sh_access_token')
    localStorage.removeItem('sh_refresh_token')
    api.setToken(null)
    set({ accessToken: null, refreshToken: null, user: null, items: [] })
  },

  setUser(user) {
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
