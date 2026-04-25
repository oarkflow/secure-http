import { Navigate, Outlet, useLocation } from 'react-router-dom'

import { useAuth } from '../auth/AuthContext'

export function ProtectedRoute() {
  const auth = useAuth()
  const location = useLocation()

  if (auth.initializing) {
    return (
      <div className="center-state">
        <div className="status-card">
          <span className="status-kicker">Restoring</span>
          <h2>Reconnecting secure session</h2>
          <p>Checking cookie-backed auth and bootstrapping the encrypted client.</p>
        </div>
      </div>
    )
  }

  if (!auth.isAuthenticated) {
    return <Navigate to="/login" replace state={{ from: location.pathname }} />
  }

  return <Outlet />
}
