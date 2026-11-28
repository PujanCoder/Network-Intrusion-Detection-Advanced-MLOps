import { useState } from "react";

import { useAuth } from "../lib/auth";

export function LoginPage() {
  const auth = useAuth();
  const [key, setKey] = useState("");

  return (
    <div className="auth-screen">
      <div className="auth-card">
        <div className="brand auth-brand">
          <div className="brand-mark">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#24d4e2" strokeWidth="1.6">
              <path d="M12 3 5 6v5.5c0 4.4 2.9 8.2 7 9.5 4.1-1.3 7-5.1 7-9.5V6l-7-3Z" />
              <path d="m9 12 2 2 4-4" stroke="#8d6bff" />
            </svg>
          </div>
          <div>
            <div className="brand-title">NDR SENTINEL</div>
            <div className="brand-sub">security operations console</div>
          </div>
        </div>

        <h1>Operator sign-in</h1>
        <p className="muted small">
          Enter the deployment API key. It is verified on the server and exchanged for an HttpOnly
          session cookie: the key is never stored in the browser, the bundle or the URL.
        </p>

        <form
          onSubmit={(event) => {
            event.preventDefault();
            if (key.trim()) void auth.signIn(key.trim()).catch(() => undefined);
          }}
        >
          <label className="field">
            <span>API key</span>
            <input
              type="password"
              autoFocus
              autoComplete="current-password"
              value={key}
              onChange={(event) => setKey(event.target.value)}
              placeholder="NDR_API_KEY"
            />
          </label>
          {auth.error && <div className="error-box">{auth.error}</div>}
          <button type="submit" className="button primary block" disabled={auth.busy || !key.trim()}>
            {auth.busy ? "Verifying…" : "Sign in"}
          </button>
        </form>

        <p className="muted tiny auth-foot">
          Sessions expire after the configured TTL. Signing out clears the cookie server-side.
        </p>
      </div>
    </div>
  );
}

export function UnconfiguredScreen() {
  return (
    <div className="auth-screen">
      <div className="auth-card">
        <h1>Deployment not configured</h1>
        <p className="small">
          This service has no API key, so every data endpoint is closed by design. Set{" "}
          <span className="mono">NDR_API_KEY</span> in the hosting environment and redeploy. The
          dashboard will then ask for that key once.
        </p>
        <a className="button" href="/api/v1/health">
          Open health endpoint
        </a>
      </div>
    </div>
  );
}
