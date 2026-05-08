import { useState, useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../../api/client'
import { useVaultStore } from '../../store/vault-store'
import {
  initCrypto,
  derive_master_key,
  derive_subkeys,
  encrypt,
  decrypt,
  generate_zkp_keypair,
  create_zkp_proof,
  toBase64,
  fromBase64,
} from '../../crypto/wasm-bridge'

function ShieldIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    </svg>
  )
}

function EyeIcon({ open }: { open: boolean }) {
  return open ? (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
      <circle cx="12" cy="12" r="3" />
    </svg>
  ) : (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24" />
      <line x1="1" y1="1" x2="23" y2="23" />
    </svg>
  )
}

function LockIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
      <path d="M7 11V7a5 5 0 0 1 10 0v4" />
    </svg>
  )
}

function Spinner() {
  return (
    <svg className="animate-spin h-5 w-5" viewBox="0 0 24 24">
      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
    </svg>
  )
}

function passwordStrength(password: string): { label: string; color: string; width: number } {
  let score = 0
  if (password.length >= 12) score++
  if (/[A-Z]/.test(password)) score++
  if (/[a-z]/.test(password)) score++
  if (/[0-9]/.test(password)) score++
  if (/[^A-Za-z0-9]/.test(password)) score++

  const levels = [
    { label: 'Too weak', color: 'bg-rose-500', width: 10 },
    { label: 'Weak', color: 'bg-rose-500', width: 30 },
    { label: 'Fair', color: 'bg-amber-500', width: 50 },
    { label: 'Good', color: 'bg-emerald-500', width: 70 },
    { label: 'Strong', color: 'bg-emerald-500', width: 90 },
    { label: 'Excellent', color: 'bg-emerald-400', width: 100 },
  ]
  return levels[score]
}

export default function Login() {
  const [mode, setMode] = useState<'login' | 'register'>('login')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const setTokens = useVaultStore((s) => s.setTokens)
  const setUser = useVaultStore((s) => s.setUser)
  const setCryptoKeys = useVaultStore((s) => s.setCryptoKeys)
  const navigate = useNavigate()

  const strength = useMemo(() => passwordStrength(password), [password])

  const randomBytes = (len: number) => {
    const buf = new Uint8Array(len)
    crypto.getRandomValues(buf)
    return buf
  }

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      await initCrypto()

      // Retrieve stored salt
      const saltStr = localStorage.getItem('sh_salt')
      if (!saltStr) {
        setError('No local credentials found. Please register first.')
        setLoading(false)
        return
      }
      const salt = new Uint8Array(saltStr.split(',').map(Number))

      // Derive master key and subkeys
      const mk = derive_master_key(password, salt)
      const keys = derive_subkeys(mk)
      const kek = new Uint8Array(keys.kek as ArrayBuffer)
      const zkpScalar = new Uint8Array(keys.zkp_scalar as ArrayBuffer)

      // Get challenge from server
      const chal = await api.challenge(email)
      const challengeBytes = fromBase64(chal.challenge)

      // Create ZKP proof using real crypto
      const kp = generate_zkp_keypair(zkpScalar)
      const proof = create_zkp_proof(new Uint8Array(kp.private_key as ArrayBuffer), challengeBytes)

      const verifyRes = await api.verify({
        challenge_id: chal.challenge_id,
        proof_t: toBase64(new Uint8Array(proof.t as ArrayBuffer)),
        proof_s: toBase64(new Uint8Array(proof.s as ArrayBuffer)),
      })

      // Fetch vault key wrap and decrypt
      const meRes = await api.me()
      const vaultKeyWrap = fromBase64(meRes.vault_key_wrap)
      const vaultKey = decrypt(kek, vaultKeyWrap, new TextEncoder().encode('vault-key-wrap-v1'))

      setTokens(verifyRes.access_token, verifyRes.refresh_token)
      setUser({ id: meRes.id, email: meRes.email })
      setCryptoKeys(salt, mk, zkpScalar, kek, vaultKey)
      navigate('/')
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

      const salt = randomBytes(32)
      const mk = derive_master_key(password, salt)
      const keys = derive_subkeys(mk)
      const kek = new Uint8Array(keys.kek as ArrayBuffer)
      const zkpScalar = new Uint8Array(keys.zkp_scalar as ArrayBuffer)

      // Generate ZKP keypair from zkp_scalar
      const kp = generate_zkp_keypair(zkpScalar)
      const zkpPublicKey = new Uint8Array(kp.public_key as ArrayBuffer)

      // Generate random vault key and wrap it with KEK
      const vaultKey = randomBytes(32)
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
      const challengeBytes = fromBase64(chal.challenge)

      const proof = create_zkp_proof(new Uint8Array(kp.private_key as ArrayBuffer), challengeBytes)

      const verifyRes = await api.verify({
        challenge_id: chal.challenge_id,
        proof_t: toBase64(new Uint8Array(proof.t as ArrayBuffer)),
        proof_s: toBase64(new Uint8Array(proof.s as ArrayBuffer)),
      })

      setTokens(verifyRes.access_token, verifyRes.refresh_token)
      setUser({ id: '', email })
      setCryptoKeys(salt, mk, zkpScalar, kek, vaultKey)
      navigate('/')
    } catch (err: any) {
      setError(err.message || 'Registration failed')
    }
    setLoading(false)
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-950 relative overflow-hidden">
      {/* Background gradient orbs */}
      <div className="absolute top-0 left-1/4 w-96 h-96 bg-emerald-500/5 rounded-full blur-3xl" />
      <div className="absolute bottom-0 right-1/4 w-96 h-96 bg-cyan-500/5 rounded-full blur-3xl" />

      <div className="relative w-full max-w-md mx-4">
        {/* Logo */}
        <div className="flex justify-center mb-8">
          <div className="flex items-center gap-3">
            <div className="w-12 h-12 bg-gradient-to-br from-emerald-500 to-cyan-500 rounded-xl flex items-center justify-center shadow-lg shadow-emerald-500/20">
              <ShieldIcon className="w-7 h-7 text-white" />
            </div>
            <div>
              <h1 className="text-2xl font-bold tracking-tight text-white">SafeHaven</h1>
              <p className="text-xs text-slate-400">Zero-knowledge secrets vault</p>
            </div>
          </div>
        </div>

        {/* Card */}
        <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl backdrop-blur-sm p-8 space-y-6">
          <div className="text-center">
            <h2 className="text-xl font-semibold text-white">
              {mode === 'login' ? 'Welcome back' : 'Create your vault'}
            </h2>
            <p className="text-sm text-slate-400 mt-1">
              {mode === 'login'
                ? 'Enter your credentials to unlock your vault'
                : 'Your data is encrypted before it leaves your device'}
            </p>
          </div>

          <form onSubmit={mode === 'login' ? handleLogin : handleRegister} className="space-y-5">
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-1.5">Email</label>
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full px-4 py-2.5 bg-slate-900 border border-slate-700 rounded-lg text-slate-100 placeholder-slate-500 transition-all duration-200"
                placeholder="you@example.com"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-slate-300 mb-1.5">Master Password</label>
              <div className="relative">
                <input
                  type={showPassword ? 'text' : 'password'}
                  required
                  minLength={12}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full px-4 py-2.5 pr-12 bg-slate-900 border border-slate-700 rounded-lg text-slate-100 placeholder-slate-500 transition-all duration-200"
                  placeholder="Minimum 12 characters"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 transition-colors"
                >
                  <EyeIcon open={showPassword} />
                </button>
              </div>
              {mode === 'register' && password.length > 0 && (
                <div className="mt-2">
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs text-slate-400">Password strength</span>
                    <span className={`text-xs font-medium ${strength.color.replace('bg-', 'text-')}`}>{strength.label}</span>
                  </div>
                  <div className="h-1.5 bg-slate-800 rounded-full overflow-hidden">
                    <div className={`h-full ${strength.color} rounded-full transition-all duration-300`} style={{ width: `${strength.width}%` }} />
                  </div>
                </div>
              )}
            </div>

            {error && (
              <div className="flex items-start gap-2 p-3 rounded-lg bg-rose-500/10 border border-rose-500/20 text-rose-400 text-sm">
                <LockIcon className="w-4 h-4 mt-0.5 flex-shrink-0" />
                <span>{error}</span>
              </div>
            )}

            <button type="submit" disabled={loading} className="w-full py-3 px-4 bg-emerald-600 hover:bg-emerald-500 text-white font-medium rounded-lg transition-colors duration-200 flex items-center justify-center gap-2">
              {loading ? <><Spinner /> Processing…</> : mode === 'login' ? 'Unlock Vault' : 'Create Vault'}
            </button>
          </form>

          <div className="text-center text-sm text-slate-400">
            {mode === 'login' ? (
              <>
                No vault yet?{' '}
                <button onClick={() => { setMode('register'); setError(''); }} className="text-emerald-400 hover:text-emerald-300 font-medium transition-colors">
                  Create one
                </button>
              </>
            ) : (
              <>
                Already have a vault?{' '}
                <button onClick={() => { setMode('login'); setError(''); }} className="text-emerald-400 hover:text-emerald-300 font-medium transition-colors">
                  Unlock it
                </button>
              </>
            )}
          </div>
        </div>

        {/* Footer */}
        <p className="text-center text-xs text-slate-600 mt-6">
          🔒 Your master password never leaves this device. Server cannot decrypt your data.
        </p>
      </div>
    </div>
  )
}
