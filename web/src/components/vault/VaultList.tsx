import { useEffect, useState, useMemo } from 'react'
import { api } from '../../api/client'
import { useVaultStore } from '../../store/vault-store'
import type { VaultItemSync } from '../../api/client'
import VaultSidebar from './VaultSidebar'

const ITEM_TYPE_ICONS: Record<string, string> = {
  password: '🔑',
  secure_note: '📝',
  credit_card: '💳',
  identity: '🪪',
  ssh_key: '🔒',
  api_key: '⚡',
  file: '📎',
  folder: '📁',
}

const ITEM_TYPE_COLORS: Record<string, string> = {
  password: 'from-amber-500/20 to-orange-500/20 text-amber-400',
  secure_note: 'from-cyan-500/20 to-blue-500/20 text-cyan-400',
  credit_card: 'from-emerald-500/20 to-teal-500/20 text-emerald-400',
  identity: 'from-violet-500/20 to-purple-500/20 text-violet-400',
  ssh_key: 'from-rose-500/20 to-pink-500/20 text-rose-400',
  api_key: 'from-yellow-500/20 to-amber-500/20 text-yellow-400',
  file: 'from-slate-500/20 to-gray-500/20 text-slate-400',
  folder: 'from-slate-500/20 to-gray-500/20 text-slate-400',
}

function SearchIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="11" cy="11" r="8" />
      <path d="m21 21-4.3-4.3" />
    </svg>
  )
}

function PlusIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <line x1="12" y1="5" x2="12" y2="19" />
      <line x1="5" y1="12" x2="19" y2="12" />
    </svg>
  )
}

function StarIcon({ filled }: { filled: boolean }) {
  return filled ? (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor" stroke="currentColor" strokeWidth="2" className="text-amber-400">
      <polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2" />
    </svg>
  ) : (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="text-slate-600">
      <polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2" />
    </svg>
  )
}

function TrashIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="3 6 5 6 21 6" />
      <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" />
    </svg>
  )
}

function CopyIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
      <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
    </svg>
  )
}

function EmptyState() {
  return (
    <div className="flex flex-col items-center justify-center py-20 text-center">
      <div className="w-20 h-20 bg-slate-800/50 rounded-2xl flex items-center justify-center mb-6">
        <span className="text-4xl">🔐</span>
      </div>
      <h3 className="text-xl font-semibold text-white mb-2">Your vault is empty</h3>
      <p className="text-slate-400 max-w-sm mb-6">Store passwords, secure notes, credit cards, and more. Everything is encrypted before it leaves your device.</p>
    </div>
  )
}

function VaultCard({ item, onDelete }: { item: VaultItemSync; onDelete: (id: string) => void }) {
  const [expanded, setExpanded] = useState(false)
  const [copied, setCopied] = useState(false)
  const icon = ITEM_TYPE_ICONS[item.item_type] || '📄'
  const colorClass = ITEM_TYPE_COLORS[item.item_type] || ITEM_TYPE_COLORS.file

  const handleCopy = () => {
    navigator.clipboard.writeText(item.blob_id)
    setCopied(true)
    setTimeout(() => setCopied(false), 1500)
  }

  return (
    <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl backdrop-blur-sm group hover:bg-slate-800 hover:border-slate-600 transition-all duration-200">
      <div className="p-5">
        <div className="flex items-start gap-4">
          {/* Icon */}
          <div className={`w-12 h-12 rounded-xl bg-gradient-to-br ${colorClass} flex items-center justify-center text-2xl flex-shrink-0`}>
            {icon}
          </div>

          {/* Content */}
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-1">
              <h3 className="font-semibold text-white truncate capitalize">
                {item.item_type.replace('_', ' ')}
              </h3>
              {item.favorite && <StarIcon filled />}
            </div>
            <p className="text-sm text-slate-400 mb-2">
              Updated {new Date(item.updated_at).toLocaleDateString()}
            </p>
            {item.tags.length > 0 && (
              <div className="flex flex-wrap gap-1.5">
                {item.tags.map((tag) => (
                  <span key={tag} className="text-xs px-2 py-0.5 bg-slate-700/50 text-slate-300 rounded-full">
                    {tag}
                  </span>
                ))}
              </div>
            )}
          </div>

          {/* Actions */}
          <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
            <button onClick={handleCopy} className="px-3 py-2 text-slate-400 hover:text-slate-100 hover:bg-slate-800 rounded-lg transition-colors duration-200" title="Copy blob ID">
              {copied ? <span className="text-emerald-400 text-xs">Copied</span> : <CopyIcon />}
            </button>
            <button onClick={() => setExpanded(!expanded)} className="px-3 py-2 text-slate-400 hover:text-slate-100 hover:bg-slate-800 rounded-lg transition-colors duration-200" title="Details">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="12" cy="12" r="1" /><circle cx="19" cy="12" r="1" /><circle cx="5" cy="12" r="1" />
              </svg>
            </button>
            <button onClick={() => onDelete(item.id)} className="btn-ghost p-2 text-rose-400 hover:text-rose-300" title="Delete">
              <TrashIcon />
            </button>
          </div>
        </div>

        {expanded && (
          <div className="mt-4 pt-4 border-t border-slate-700/50 space-y-2 text-sm text-slate-400">
            <div className="flex justify-between">
              <span>ID</span>
              <span className="font-mono text-slate-300">{item.id.slice(0, 16)}…</span>
            </div>
            <div className="flex justify-between">
              <span>Blob ID</span>
              <span className="font-mono text-slate-300">{item.blob_id.slice(0, 16)}…</span>
            </div>
            <div className="flex justify-between">
              <span>Version</span>
              <span className="text-slate-300">{item.version}</span>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

export default function VaultList() {
  const items = useVaultStore((s) => s.items)
  const setItems = useVaultStore((s) => s.setItems)
  const removeItem = useVaultStore((s) => s.removeItem)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [search, setSearch] = useState('')
  const [filter, setFilter] = useState('all')
  const [showAddModal, setShowAddModal] = useState(false)

  useEffect(() => {
    api.sync(undefined, true)
      .then((res) => {
        setItems(res.items.filter((i) => !i.deleted))
        setLoading(false)
      })
      .catch((err) => {
        setError(err.message)
        setLoading(false)
      })
  }, [setItems])

  const filtered = useMemo(() => {
    let result = items
    if (filter !== 'all') {
      if (filter === 'favorite') {
        result = result.filter((i) => i.favorite)
      } else {
        result = result.filter((i) => i.item_type === filter)
      }
    }
    if (search.trim()) {
      const q = search.toLowerCase()
      result = result.filter((i) =>
        i.item_type.toLowerCase().includes(q) ||
        i.tags.some((t) => t.toLowerCase().includes(q))
      )
    }
    return result
  }, [items, filter, search])

  const handleDelete = async (id: string) => {
    try {
      await api.deleteVaultItem(id)
      removeItem(id)
    } catch (err: any) {
      setError(err.message)
    }
  }

  return (
    <div className="flex min-h-screen bg-slate-950">
      <VaultSidebar activeFilter={filter} onFilterChange={setFilter} />

      <div className="flex-1 flex flex-col">
        {/* Top bar */}
        <header className="h-16 border-b border-slate-800 bg-slate-900/50 backdrop-blur-sm flex items-center px-6 gap-4">
          <div className="flex-1 relative max-w-xl">
            <div className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500">
              <SearchIcon />
            </div>
            <input
              type="text"
              placeholder="Search vault…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full pl-10 pr-4 py-2 bg-slate-800/50 border border-slate-700/50 rounded-lg text-sm text-slate-100 placeholder-slate-500 focus:ring-2 focus:ring-emerald-500/50 focus:border-emerald-500"
            />
          </div>
          <button onClick={() => setShowAddModal(true)} className="px-4 py-2.5 bg-emerald-600 hover:bg-emerald-500 text-white font-medium rounded-lg transition-colors duration-200 flex items-center justify-center gap-2">
            <PlusIcon />
            <span>Add Item</span>
          </button>
        </header>

        {/* Content */}
        <main className="flex-1 p-6 overflow-y-auto scrollbar-thin">
          {loading ? (
            <div className="flex items-center justify-center py-20">
              <div className="animate-spin w-8 h-8 border-2 border-emerald-500 border-t-transparent rounded-full" />
            </div>
          ) : error ? (
            <div className="p-4 bg-rose-500/10 border border-rose-500/20 rounded-lg text-rose-400 text-sm">
              {error}
            </div>
          ) : filtered.length === 0 ? (
            <EmptyState />
          ) : (
            <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-4">
              {filtered.map((item) => (
                <VaultCard key={item.id} item={item} onDelete={handleDelete} />
              ))}
            </div>
          )}
        </main>
      </div>

      {/* Add Item Modal */}
      {showAddModal && <AddItemModal onClose={() => setShowAddModal(false)} />}
    </div>
  )
}

function AddItemModal({ onClose }: { onClose: () => void }) {
  const addItem = useVaultStore((s) => s.addItem)
  const [itemType, setItemType] = useState('password')
  const [loading, setLoading] = useState(false)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    try {
      const blob = crypto.getRandomValues(new Uint8Array(64))
      const res = await api.createVaultItem({
        item_type: itemType,
        blob: btoa(String.fromCharCode(...blob)),
        blob_size: blob.length,
        tags: ['demo'],
        favorite: false,
      })
      addItem({
        id: res.id,
        blob_id: res.blob_id,
        item_type: itemType,
        version: res.version,
        updated_at: res.created_at,
        deleted: false,
        tags: ['demo'],
        favorite: false,
      })
      onClose()
    } catch (err: any) {
      alert(err.message)
    }
    setLoading(false)
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm" onClick={onClose}>
      <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl backdrop-blur-sm w-full max-w-md mx-4 p-6" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-xl font-semibold text-white">Add Item</h2>
          <button onClick={onClose} className="px-3 py-1 text-slate-400 hover:text-slate-100 hover:bg-slate-800 rounded-lg transition-colors duration-200">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" />
            </svg>
          </button>
        </div>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-1.5">Item Type</label>
            <select
              value={itemType}
              onChange={(e) => setItemType(e.target.value)}
              className="w-full px-4 py-2.5 bg-slate-900 border border-slate-700 rounded-lg text-slate-100"
            >
              <option value="password">Password</option>
              <option value="secure_note">Secure Note</option>
              <option value="credit_card">Credit Card</option>
              <option value="identity">Identity</option>
              <option value="ssh_key">SSH Key</option>
              <option value="api_key">API Key</option>
            </select>
          </div>
          <div className="flex justify-end gap-3 pt-2">
            <button type="button" onClick={onClose} className="px-4 py-2.5 bg-slate-800 hover:bg-slate-700 text-slate-200 font-medium rounded-lg border border-slate-700 transition-colors duration-200 flex items-center justify-center gap-2">Cancel</button>
            <button type="submit" disabled={loading} className="btn-primary">
              {loading ? 'Saving…' : 'Save Item'}
            </button>
          </div>
        </form>
      </div>
    </div>

)
}
