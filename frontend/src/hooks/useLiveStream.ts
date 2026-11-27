import { useEffect, useRef, useState } from "react";

import type { NetworkEvent, Overview } from "../lib/api";
import { wsUrl } from "../lib/api";

export interface LiveState {
  connected: boolean;
  everConnected: boolean;
  reconnects: number;
  sensor: { sensor_id: string; mode: string } | null;
  model: { name: string; version: string; loaded: boolean } | null;
  overview: Overview | null;
  events: NetworkEvent[];
  lastMessageAt: number | null;
  lastEventAt: number | null;
  sessionEvents: number;
  sessionAttacks: number;
}

const initialState: LiveState = {
  connected: false,
  everConnected: false,
  reconnects: 0,
  sensor: null,
  model: null,
  overview: null,
  events: [],
  lastMessageAt: null,
  lastEventAt: null,
  sessionEvents: 0,
  sessionAttacks: 0,
};

export function useLiveStream(maxEvents = 400) {
  const [state, setState] = useState<LiveState>(initialState);
  const pausedRef = useRef(false);
  const bufferRef = useRef<NetworkEvent[]>([]);
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
          reconnects: prev.everConnected ? prev.reconnects + 1 : 0,
        }));
      };

      socket.onmessage = (message) => {
        let payload: any;
        try {
          payload = JSON.parse(message.data);
        } catch {
          return;
        }
        if (payload.type === "hello") {
          setState((prev) => ({
            ...prev,
            sensor: payload.sensor ?? prev.sensor,
            model: payload.model ?? prev.model,
            overview: payload.overview ?? prev.overview,
            lastMessageAt: Date.now(),
          }));
          return;
        }
        if (payload.type === "event" && payload.event) {
          const event = payload.event as NetworkEvent;
          bufferRef.current = [event, ...bufferRef.current].slice(0, maxEvents);
          setState((prev) => ({
            ...prev,
            events: pausedRef.current ? prev.events : bufferRef.current,
            lastEventAt: Date.now(),
            lastMessageAt: Date.now(),
            sessionEvents: prev.sessionEvents + 1,
            sessionAttacks: prev.sessionAttacks + (event.is_malicious ? 1 : 0),
          }));
          return;
        }
        if (payload.type === "metrics" && payload.overview) {
          setState((prev) => ({
            ...prev,
            overview: payload.overview,
            lastMessageAt: Date.now(),
          }));
          return;
        }
        if (payload.type === "ping") {
          setState((prev) => ({ ...prev, lastMessageAt: Date.now() }));
        }
      };

      socket.onclose = () => {
        setState((prev) => ({ ...prev, connected: false }));
        if (disposed) return;
        attempts += 1;
        const delay = Math.min(8000, 500 * 2 ** Math.min(attempts, 4));
        retryTimer = window.setTimeout(connect, delay);
      };

      socket.onerror = () => {
        socket.close();
      };
    };

    connect();

    return () => {
      disposed = true;
      if (retryTimer) window.clearTimeout(retryTimer);
      socketRef.current?.close();
    };
  }, [maxEvents]);

  const setPaused = (paused: boolean) => {
    pausedRef.current = paused;
    if (!paused) {
      setState((prev) => ({ ...prev, events: bufferRef.current }));
    }
  };

  const clearEvents = () => {
    bufferRef.current = [];
    setState((prev) => ({ ...prev, events: [] }));
  };

  return { ...state, setPaused, clearEvents };
}
