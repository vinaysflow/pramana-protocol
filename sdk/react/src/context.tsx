"use client";

import React, {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useState,
  type ReactNode,
} from "react";

// ---------------------------------------------------------------------------
// Context shape
// ---------------------------------------------------------------------------

export interface PramanaContextValue {
  /** Base URL of the Pramana backend API (e.g. "http://localhost:8000").
   *  When null, server-connected hooks will throw on use. */
  apiUrl: string | null;
  /** Current bearer token for authenticated API requests. */
  authToken: string | null;
  /** Update the stored auth token (e.g. after a demo session is created). */
  setAuthToken: (token: string | null) => void;
}

const PramanaContext = createContext<PramanaContextValue>({
  apiUrl: null,
  authToken: null,
  setAuthToken: () => undefined,
});

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

export interface PramanaProviderProps {
  children: ReactNode;
  /** Optional. Base URL of the backend API. Enables server-connected hooks. */
  apiUrl?: string | null;
  /** Optional. Initial auth bearer token. Can be changed via setAuthToken(). */
  authToken?: string | null;
}

export function PramanaProvider({
  children,
  apiUrl = null,
  authToken: initialToken = null,
}: PramanaProviderProps): React.JSX.Element {
  const [authToken, setAuthTokenState] = useState<string | null>(initialToken);

  const setAuthToken = useCallback((token: string | null) => {
    setAuthTokenState(token);
  }, []);

  const value = useMemo<PramanaContextValue>(
    () => ({ apiUrl: apiUrl ?? null, authToken, setAuthToken }),
    [apiUrl, authToken, setAuthToken],
  );

  return (
    <PramanaContext.Provider value={value}>{children}</PramanaContext.Provider>
  );
}

// ---------------------------------------------------------------------------
// Hook: usePramana (internal — access raw context)
// ---------------------------------------------------------------------------

export function usePramana(): PramanaContextValue {
  return useContext(PramanaContext);
}

/** Asserts that apiUrl is configured; throws a clear message otherwise. */
export function useRequireApiUrl(): string {
  const { apiUrl } = usePramana();
  if (!apiUrl) {
    throw new Error(
      "[PramanaProvider] apiUrl is required for server-connected hooks. " +
        "Pass apiUrl prop to <PramanaProvider>.",
    );
  }
  return apiUrl;
}
