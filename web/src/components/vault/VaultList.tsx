import { useEffect, useState } from 'react'
import { api } from '../../api/client'
import { useVaultStore } from '../../store/vault-store'
import type { VaultItemSync } from '../../api/client'

export default function VaultList() {
  const items = useVaultStore((s) => s.items)
  const setItems = useVaultStore((s) => s.setItems)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [search, setSearch] = useState('')

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

  const filtered = items.filter((i) =>
    i.item_type.toLowerCase().includes(search.toLowerCase())
  )

  const handleDelete = async (id: string) => {
    try {
      await api.deleteVaultItem(id)
      useVaultStore.getState().removeItem(id)
    } catch (err: any) {
      setError(err.message)
    }
  }

  if (loading) return <p className="text-gray-600">Loading vault…</p>
  if (error) return <p className="text-red-600">{error}</p>

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-xl font-semibold">Your Vault</h2>
        <input
          type="text"
          placeholder="Search…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="px-3 py-1.5 border rounded text-sm w-64"
        />
      </div>
      {filtered.length === 0 ? (
        <p className="text-gray-500">No items found.</p>
      ) : (
        <ul className="space-y-3">
          {filtered.map((item) => (
            <VaultItemRow key={item.id} item={item} onDelete={handleDelete} />
          ))}
        </ul>
      )}
    </div>
  )
}

function VaultItemRow({ item, onDelete }: { item: VaultItemSync; onDelete: (id: string) => void }) {
  const [expanded, setExpanded] = useState(false)

  return (
    <li className="border rounded bg-white p-4">
      <div className="flex items-center justify-between">
        <button onClick={() => setExpanded(!expanded)} className="flex items-center gap-3">
          <span className="text-lg">{item.favorite ? '★' : '☆'}</span>
          <span className="font-medium capitalize">{item.item_type.replace('_', ' ')}</span>
          <span className="text-xs text-gray-500">v{item.version}</span>
        </button>
        <button
          onClick={() => onDelete(item.id)}
          className="text-sm text-red-600 hover:underline"
        >
          Delete
        </button>
      </div>
      {expanded && (
        <div className="mt-3 text-sm text-gray-700">
          <p>ID: {item.id}</p>
          <p>Blob ID: {item.blob_id}</p>
          <p>Tags: {item.tags.length ? item.tags.join(', ') : 'none'}</p>
          <p>Updated: {new Date(item.updated_at).toLocaleString()}</p>
        </div>
      )}
    </li>
  )
}
