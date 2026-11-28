import { useCallback, useEffect, useRef, useState } from "react";

import type { Detection, Overview } from "../lib/api";
import { wsUrl } from "../lib/api";

export interface LiveState {
  connected: boolean;
  everConnected: boolean;
  reconnects: number;
  hello: Overview | null;
  events: Detection[];
  lastMessageAt: number | null;
  lastEventAt: number | null;
  sessionEvents: number;
  sessionAttacks: number;
  unauthorized: boolean;
}

const initialState: LiveState = {
  connected: false,
  everConnected: false,
  reconnects: 0,
  hello: null,
  events: [],
  lastMessageAt: null,
  lastEventAt: null,
  sessionEvents: 0,
  sessionAttacks: 0,
  unauthorized: false,
};

export type LiveStream = LiveState & {
  setPaused: (paused: boolean) => void;
  clearEvents: () => void;
};

/**
 * Alert stream over the authenticated WebSocket.
 *
 * The browser authenticates with the HttpOnly session cookie, so no key appears
 * in the URL. Events arrive as `{type: "event", event}` and are de-duplicated by
 * detection id, which keeps a reconnect from replaying the same rows as new.
 */
export function useLiveStream(maxEvents = 500): LiveStream {
  const [state, setState] = useState<LiveState>(initialState);
  const pausedRef = useRef(false);
  const bufferRef = useRef<Detection[]>([]);
  const seenRef = useRef<Set<string>>(new Set());
  const socketRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    let disposed = false;
    let retryTimer: number | undefined;
    let attempts = 0;

    const connect = () => {
      if (disposed) return;
      const socket = new WebSocket(wsUrl());
      socketRef.current = socket;

      socket.onopen = () => {
        attempts = 0;
        setState((prev) => ({
          ...prev,
          connected: true,
          everConnected: true,
          unauthorized: false,
          reconnects: prev.everConnected ? prev.reconnects + 1 : 0,
        }));
      };

      socket.onmessage = (message) => {
        let payload: { type?: string; event?: Detection; overview?: Overview };
        try {
          payload = JSON.parse(message.data);
        } catch {
          return;
        }
        if (payload.type === "hello") {
          setState((prev) => ({ ...prev, hello: payload.overview ?? prev.hello, lastMessageAt: Date.now() }));
          return;
        }
        if (payload.type === "event" && payload.event) {
          const event = payload.event;
          if (seenRef.current.has(event.id)) return;
          seenRef.current.add(event.id);
          bufferRef.current = [event, ...bufferRef.current].slice(0, maxEvents);
          setState((prev) => ({
            ...prev,
            events: pausedRef.current ? prev.events : bufferRef.current,
            lastEventAt: Date.now(),
            lastMessageAt: Date.now(),
            sessionEvents: prev.sessionEvents + 1,
            sessionAttacks: prev.sessionAttacks + (event.is_attack ? 1 : 0),
          }));
        }
      };

      socket.onclose = (closeEvent) => {
        setState((prev) => ({ ...prev, connected: false }));
        if (disposed) return;
        if (closeEvent.code === 1008) {
          setState((prev) => ({ ...prev, unauthorized: true }));
        }
        attempts += 1;
        const delay = Math.min(8000, 500 * 2 ** Math.min(attempts, 4));
        retryTimer = window.setTimeout(connect, delay);
      };

      socket.onerror = () => socket.close();
    };

    connect();

    return () => {
      disposed = true;
      if (retryTimer) window.clearTimeout(retryTimer);
      socketRef.current?.close();
    };
  }, [maxEvents]);

  const setPaused = useCallback((paused: boolean) => {
    pausedRef.current = paused;
    if (!paused) setState((prev) => ({ ...prev, events: bufferRef.current }));
  }, []);

  const clearEvents = useCallback(() => {
    bufferRef.current = [];
    seenRef.current = new Set();
    setState((prev) => ({ ...prev, events: [] }));
  }, []);

  return { ...state, setPaused, clearEvents };
}
