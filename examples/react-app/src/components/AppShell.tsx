import { NavLink, Outlet } from 'react-router-dom'

import { useAuth } from '../auth/AuthContext'

export function AppShell() {
  const auth = useAuth()

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand-block">
          <p className="eyebrow">Secure HTTP</p>
          <h1>Ops Workspace</h1>
          <p className="lede">
            Encrypted browser transport with cookie auth, CSRF protection, and a Fiber backend.
          </p>
        </div>

        <nav className="nav-list" aria-label="Primary">
          <NavLink
            to="/app"
            end
            className={({ isActive }) => (isActive ? 'nav-link active' : 'nav-link')}
          >
            Overview
          </NavLink>
          <NavLink
            to="/app/todos"
            className={({ isActive }) => (isActive ? 'nav-link active' : 'nav-link')}
          >
            Todos
          </NavLink>
        </nav>

        <div className="session-card">
          <span className="session-label">Session</span>
          <strong>{auth.identity || 'Anonymous'}</strong>
          <span className="session-meta">{auth.status}</span>
          <button type="button" className="secondary-button" onClick={() => void auth.logout()}>
            Sign out
          </button>
        </div>
      </aside>

      <main className="main-panel">
        <Outlet />
      </main>
    </div>
  )
}
