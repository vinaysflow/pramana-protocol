/**
 * Internal fetch helpers used by server-connected hooks.
 * Mirror the pattern in frontend/lib/api.ts, but receive apiUrl/authToken
 * as parameters rather than reading from localStorage.
 */

async function formatError(res: Response): Promise<string> {
  const rid =
    res.headers.get("x-request-id") ||
    res.headers.get("X-Request-ID") ||
    "";
  const ct = res.headers.get("content-type") || "";
  const text = await res.text();

  if (ct.includes("application/json")) {
    try {
      const data = JSON.parse(text) as Record<string, unknown>;
      const msg =
        typeof data?.error === "string" ? data.error : text;
      const reqId =
        typeof data?.request_id === "string" ? data.request_id : rid;
      return reqId ? `${msg} (request_id=${reqId})` : msg;
    } catch {
      // fall through
    }
  }
  return rid ? `${text} (request_id=${rid})` : text;
}

function authHeaders(token: string | null): Record<string, string> {
  return token ? { Authorization: `Bearer ${token}` } : {};
}

export async function apiPost<T>(
  apiUrl: string,
  path: string,
  body: unknown,
  token: string | null = null,
): Promise<T> {
  const res = await fetch(`${apiUrl}${path}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...authHeaders(token),
    },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const msg = await formatError(res);
    throw new Error(`${res.status} ${res.statusText}: ${msg}`);
  }
  return (await res.json()) as T;
}

export async function apiGet<T>(
  apiUrl: string,
  path: string,
  token: string | null = null,
): Promise<T> {
  const res = await fetch(`${apiUrl}${path}`, {
    method: "GET",
    headers: { ...authHeaders(token) },
  });
  if (!res.ok) {
    const msg = await formatError(res);
    throw new Error(`${res.status} ${res.statusText}: ${msg}`);
  }
  return (await res.json()) as T;
}
