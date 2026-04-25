import { useState, type FormEvent } from 'react'
import { Navigate, useLocation } from 'react-router-dom'

import { useAuth } from '../auth/AuthContext'

export function LoginPage() {
  const auth = useAuth()
  const location = useLocation()
  const [username, setUsername] = useState('alice')
  const [password, setPassword] = useState('alice-password')
  const [error, setError] = useState('')
  const [submitting, setSubmitting] = useState(false)

  const from = typeof location.state?.from === 'string' ? location.state.from : '/app'

  if (auth.isAuthenticated) {
    return <Navigate to={from} replace />
  }

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setSubmitting(true)
    setError('')
    try {
      await auth.login({ username, password })
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Sign-in failed')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="login-layout">
      <section className="login-panel">
        <div className="login-copy">
          <p className="eyebrow">Secure transport demo</p>
          <h1>Sign in to the encrypted workspace</h1>
          <p className="lede">
            The browser logs in over Fiber auth routes, restores the CSRF cookie, then upgrades API
            traffic onto the secure HTTP bridge.
          </p>
        </div>

        <form className="login-form" onSubmit={handleSubmit}>
          <label className="field">
            <span>Username</span>
            <input
              autoComplete="username"
              value={username}
              onChange={(event) => setUsername(event.target.value)}
              placeholder="alice"
              required
            />
          </label>

          <label className="field">
            <span>Password</span>
            <input
              autoComplete="current-password"
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              placeholder="alice-password"
              required
            />
          </label>

          {(error || auth.bootstrapError) && (
            <div className="notice error">{error || auth.bootstrapError}</div>
          )}

          <button type="submit" className="primary-button" disabled={submitting}>
            {submitting ? 'Signing in...' : 'Sign in'}
          </button>
        </form>
      </section>

      <section className="login-aside">
        <div className="credential-card">
          <span className="credential-label">Sample Accounts</span>
          <div className="credential-line">
            <strong>alice</strong>
            <code>alice-password</code>
          </div>
          <div className="credential-line">
            <strong>bob</strong>
            <code>bob-password</code>
          </div>
        </div>
      </section>
    </div>
  )
}
