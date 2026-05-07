import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../../api/client'
import { useVaultStore } from '../../store/vault-store'
import { initCrypto, derive_master_key, derive_subkeys, encrypt, toBase64 } from '../../crypto/wasm-bridge'

export default function Login() {
  const [mode, setMode] = useState<'login' | 'register'>('login')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const setTokens = useVaultStore((s) => s.setTokens)
  const setUser = useVaultStore((s) => s.setUser)
  const navigate = useNavigate()

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      await initCrypto()

      // 1. Get challenge
      // Login requires local salt storage to derive the master key.
      // For this demo, registration auto-logs you in.
      setError('Login requires local salt storage. Please use register for this demo.')
      setLoading(false)
      return
    } catch (err: any) {
      setError(err.message || 'Login failed')
    }
    setLoading(false)
  }

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      await initCrypto()

      const salt = crypto.getRandomValues(new Uint8Array(32))
      const mk = derive_master_key(password, salt)
      const keys = derive_subkeys(mk)

      // Derive ZKP public key: Y = x * G
      // For demo, we use a random placeholder for scalar multiplication
      // In production, this uses Ristretto255 group operations from WASM
      const zkpPublicKey = crypto.getRandomValues(new Uint8Array(32))

      const vaultKey = crypto.getRandomValues(new Uint8Array(32))
      const kek = new Uint8Array(keys.kek as ArrayBuffer)
      const wrap = encrypt(kek, vaultKey, new TextEncoder().encode('vault-key-wrap-v1'))

      await api.register({
        email,
        zkp_public_key: toBase64(zkpPublicKey),
        argon2_salt: toBase64(salt),
        argon2_memory: 65536,
        argon2_iterations: 3,
        argon2_parallelism: 4,
        vault_key_wrap: toBase64(wrap as Uint8Array),
      })

      // Auto-login after register
      const chal = await api.challenge(email)

      // Generate ZKP proof (simplified for demo)
      const proofT = crypto.getRandomValues(new Uint8Array(32))
      const proofS = crypto.getRandomValues(new Uint8Array(32))

      const verifyRes = await api.verify({
        challenge_id: chal.challenge_id,
        proof_t: toBase64(proofT),
        proof_s: toBase64(proofS),
      })

      setTokens(verifyRes.access_token, verifyRes.refresh_token)
      setUser({ id: '', email })
      navigate('/')
    } catch (err: any) {
      setError(err.message || 'Registration failed')
    }
    setLoading(false)
  }

  return (
    <div className="max-w-md mx-auto mt-12">
      <h1 className="text-2xl font-bold mb-6">
        {mode === 'login' ? 'Sign In' : 'Create Account'}
      </h1>
      <form onSubmit={mode === 'login' ? handleLogin : handleRegister} className="space-y-4">
        <div>
          <label className="block text-sm font-medium mb-1">Email</label>
          <input
            type="email"
            required
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="w-full px-3 py-2 border rounded focus:outline-none focus:ring-2 focus:ring-gray-900"
          />
        </div>
        <div>
          <label className="block text-sm font-medium mb-1">Master Password</label>
          <input
            type="password"
            required
            minLength={12}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="w-full px-3 py-2 border rounded focus:outline-none focus:ring-2 focus:ring-gray-900"
          />
        </div>
        {error && <p className="text-red-600 text-sm">{error}</p>}
        <button
          type="submit"
          disabled={loading}
          className="w-full px-4 py-2 bg-gray-900 text-white rounded hover:bg-gray-700 disabled:opacity-50"
        >
          {loading ? 'Processing…' : mode === 'login' ? 'Sign In' : 'Create Account'}
        </button>
      </form>
      <p className="mt-4 text-sm text-center text-gray-600">
        {mode === 'login' ? (
          <>
            No account?{' '}
            <button onClick={() => setMode('register')} className="underline">
              Register
            </button>
          </>
        ) : (
          <>
            Already have an account?{' '}
            <button onClick={() => setMode('login')} className="underline">
              Sign in
            </button>
          </>
        )}
      </p>
    </div>
  )
}
