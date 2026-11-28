import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";

import { ApiError, api, UNAUTHORIZED_EVENT, type SessionState } from "./api";

type Status = "loading" | "authenticated" | "anonymous" | "unconfigured";

interface AuthValue {
  status: Status;
  session: SessionState | null;
  error: string | null;
  busy: boolean;
  signIn: (key: string) => Promise<void>;
  signOut: () => Promise<void>;
  refresh: () => Promise<void>;
}

const AuthContext = createContext<AuthValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<SessionState | null>(null);
  const [status, setStatus] = useState<Status>("loading");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const refresh = useCallback(async () => {
    try {
      const state = await api.session();
      setSession(state);
      if (!state.configured) setStatus("unconfigured");
      else setStatus(state.authenticated ? "authenticated" : "anonymous");
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
      setStatus("anonymous");
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  useEffect(() => {
    const onUnauthorized = () => setStatus((prev) => (prev === "unconfigured" ? prev : "anonymous"));
    window.addEventListener(UNAUTHORIZED_EVENT, onUnauthorized);
    return () => window.removeEventListener(UNAUTHORIZED_EVENT, onUnauthorized);
  }, []);

  const signIn = useCallback(async (key: string) => {
    setBusy(true);
    setError(null);
    try {
      await api.login(key);
      const state = await api.session();
      setSession(state);
      setStatus(state.authenticated ? "authenticated" : "anonymous");
    } catch (caught) {
      const message =
        caught instanceof ApiError && caught.status === 401
          ? "That key does not match this deployment."
          : caught instanceof Error
            ? caught.message
            : String(caught);
      setError(message);
      setStatus("anonymous");
      throw caught;
    } finally {
      setBusy(false);
    }
  }, []);

  const signOut = useCallback(async () => {
    try {
      await api.logout();
    } finally {
      setSession(null);
      setStatus("anonymous");
    }
  }, []);

  const value = useMemo<AuthValue>(
    () => ({ status, session, error, busy, signIn, signOut, refresh }),
    [status, session, error, busy, signIn, signOut, refresh],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthValue {
  const value = useContext(AuthContext);
  if (!value) throw new Error("useAuth must be used inside AuthProvider");
  return value;
}
