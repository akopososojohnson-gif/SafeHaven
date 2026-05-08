import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import Login from './components/auth/Login'
import VaultList from './components/vault/VaultList'
import { useVaultStore } from './store/vault-store'

function App() {
  const token = useVaultStore((s) => s.accessToken)

  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={token ? <VaultList /> : <Navigate to="/login" />} />
        <Route path="/login" element={!token ? <Login /> : <Navigate to="/" />} />
      </Routes>
    </BrowserRouter>
  )
}

export default App
