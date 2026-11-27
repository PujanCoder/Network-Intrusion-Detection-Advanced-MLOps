import { createContext, useContext } from "react";

import type { LiveStream } from "../hooks/useLiveStream";

export const LiveContext = createContext<LiveStream | null>(null);

export function useLive(): LiveStream {
  const value = useContext(LiveContext);
  if (value === null) {
    throw new Error("useLive must be used inside a LiveContext.Provider");
  }
  return value;
}
