import { Outlet, Link, useNavigate } from 'react-router-dom'
import { useVaultStore } from '../../store/vault-store'

export default function Layout() {
  const user = useVaultStore((s) => s.user)
  const logout = useVaultStore((s) => s.logout)
  const navigate = useNavigate()

  const handleLogout = async () => {
    await logout()
    navigate('/login')
  }

  return (
    <div className="min-h-screen bg-gray-50 text-gray-900">
      <header className="border-b bg-white px-6 py-4 flex items-center justify-between">
        <Link to="/" className="text-xl font-bold tracking-tight">
          SafeHaven
        </Link>
        <nav className="flex items-center gap-4">
          {user && (
            <>
              <span className="text-sm text-gray-600">{user.email}</span>
              <button
                onClick={handleLogout}
                className="text-sm px-3 py-1.5 rounded bg-gray-900 text-white hover:bg-gray-700"
              >
                Logout
              </button>
            </>
          )}
        </nav>
      </header>
      <main className="max-w-5xl mx-auto px-6 py-8">
        <Outlet />
      </main>
    </div>
  )
}
