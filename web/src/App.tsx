import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import Layout from './components/layout/Layout'
import Login from './components/auth/Login'
import VaultList from './components/vault/VaultList'
import { useVaultStore } from './store/vault-store'

function App() {
  const token = useVaultStore((s) => s.accessToken)

  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Layout />}>
          <Route index element={token ? <VaultList /> : <Navigate to="/login" />} />
          <Route path="login" element={!token ? <Login /> : <Navigate to="/" />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}

export default App
