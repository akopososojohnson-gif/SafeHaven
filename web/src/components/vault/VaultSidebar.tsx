import { useVaultStore } from '../../store/vault-store'

interface VaultSidebarProps {
  activeFilter: string
  onFilterChange: (filter: string) => void
}

const categories = [
  { id: 'all', label: 'All Items', icon: '🔐' },
  { id: 'password', label: 'Passwords', icon: '🔑' },
  { id: 'secure_note', label: 'Secure Notes', icon: '📝' },
  { id: 'credit_card', label: 'Credit Cards', icon: '💳' },
  { id: 'identity', label: 'Identities', icon: '🪪' },
  { id: 'ssh_key', label: 'SSH Keys', icon: '🔒' },
  { id: 'api_key', label: 'API Keys', icon: '⚡' },
]

export default function VaultSidebar({ activeFilter, onFilterChange }: VaultSidebarProps) {
  const items = useVaultStore((s) => s.items)
  const user = useVaultStore((s) => s.user)

  const counts = {
    all: items.length,
    password: items.filter((i) => i.item_type === 'password').length,
    secure_note: items.filter((i) => i.item_type === 'secure_note').length,
    credit_card: items.filter((i) => i.item_type === 'credit_card').length,
    identity: items.filter((i) => i.item_type === 'identity').length,
    ssh_key: items.filter((i) => i.item_type === 'ssh_key').length,
    api_key: items.filter((i) => i.item_type === 'api_key').length,
    favorite: items.filter((i) => i.favorite).length,
  }

  return (
    <aside className="w-64 min-h-screen bg-slate-900/80 border-r border-slate-800 flex flex-col">
      {/* Logo */}
      <div className="p-6 border-b border-slate-800">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 bg-gradient-to-br from-emerald-500 to-cyan-500 rounded-lg flex items-center justify-center">
            <svg className="w-5 h-5 text-white" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            </svg>
          </div>
          <span className="text-lg font-bold text-white tracking-tight">SafeHaven</span>
        </div>
      </div>

      {/* Categories */}
      <nav className="flex-1 p-4 space-y-1 overflow-y-auto scrollbar-thin">
        {categories.map((cat) => (
          <button
            key={cat.id}
            onClick={() => onFilterChange(cat.id)}
            className={activeFilter === cat.id ? 'flex items-center gap-3 px-3 py-2 rounded-lg text-emerald-400 bg-emerald-500/10 hover:bg-emerald-500/15 transition-all duration-200 cursor-pointer w-full' : 'flex items-center gap-3 px-3 py-2 rounded-lg text-slate-400 hover:text-slate-100 hover:bg-slate-800/80 transition-all duration-200 cursor-pointer w-full'}
          >
            <span className="text-lg">{cat.icon}</span>
            <span className="flex-1 text-left text-sm">{cat.label}</span>
            <span className="text-xs text-slate-500 bg-slate-800 px-2 py-0.5 rounded-full">
              {counts[cat.id as keyof typeof counts] || 0}
            </span>
          </button>
        ))}

        <div className="pt-4 mt-4 border-t border-slate-800">
          <button
            onClick={() => onFilterChange('favorite')}
            className={activeFilter === 'favorite' ? 'flex items-center gap-3 px-3 py-2 rounded-lg text-emerald-400 bg-emerald-500/10 hover:bg-emerald-500/15 transition-all duration-200 cursor-pointer w-full' : 'flex items-center gap-3 px-3 py-2 rounded-lg text-slate-400 hover:text-slate-100 hover:bg-slate-800/80 transition-all duration-200 cursor-pointer w-full'}
          >
            <span className="text-lg">⭐</span>
            <span className="flex-1 text-left text-sm">Favorites</span>
            <span className="text-xs text-slate-500 bg-slate-800 px-2 py-0.5 rounded-full">{counts.favorite}</span>
          </button>
        </div>
      </nav>

      {/* User */}
      {user && (
        <div className="p-4 border-t border-slate-800">
          <div className="flex items-center gap-3 px-3 py-2 rounded-lg bg-slate-800/50">
            <div className="w-8 h-8 rounded-full bg-gradient-to-br from-emerald-500 to-cyan-500 flex items-center justify-center text-white text-sm font-bold">
              {user.email[0].toUpperCase()}
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-sm text-slate-200 truncate">{user.email}</p>
              <p className="text-xs text-emerald-400">● Online</p>
            </div>
          </div>
        </div>
      )}
    </aside>
  )
}
