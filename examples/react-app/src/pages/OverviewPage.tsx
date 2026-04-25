import { Link } from 'react-router-dom'

import { useAuth } from '../auth/AuthContext'

export function OverviewPage() {
  const auth = useAuth()

  return (
    <div className="page-stack">
      <section className="hero-panel">
        <div>
          <p className="eyebrow">Authenticated</p>
          <h2>Secure channel is ready</h2>
          <p className="lede">
            Cookie auth and CSRF bootstrap are active, and the secure client is available to any
            route under this shell.
          </p>
        </div>
        <div className="metric-grid">
          <article className="metric-card">
            <span className="metric-label">Identity</span>
            <strong>{auth.identity}</strong>
          </article>
          <article className="metric-card">
            <span className="metric-label">Session State</span>
            <strong>{auth.status}</strong>
          </article>
        </div>
      </section>

      <section className="content-grid">
        <article className="panel">
          <h3>Routing</h3>
          <p>Protected routes are blocked until session restore finishes and auth is confirmed.</p>
        </article>

        <article className="panel">
          <h3>Data Access</h3>
          <p>Encrypted requests are issued through the shared secure HTTP client instance.</p>
        </article>

        <article className="panel">
          <h3>Next Step</h3>
          <p>The todo route exercises create, update, refresh, and delete against the Fiber API.</p>
          <Link to="/app/todos" className="inline-link">
            Open todo workspace
          </Link>
        </article>
      </section>
    </div>
  )
}
