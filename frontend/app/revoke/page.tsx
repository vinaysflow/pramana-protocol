"use client";

import { useState } from "react";
import { apiPost } from "../../lib/api";

export default function RevokePage() {
  const [credentialId, setCredentialId] = useState("");
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState("");

  async function revoke() {
    setError("");
    setResult(null);
    try {
      const resp = await apiPost<any>(`/v1/credentials/${credentialId}/revoke`, {});
      setResult(resp);
    } catch (e: any) {
      setError(String(e?.message || e));
    }
  }

  return (
    <main style={{ maxWidth: 900 }}>
      <h1>Revoke</h1>
      <label>
        Credential ID
        <input style={{ width: "100%" }} value={credentialId} onChange={(e) => setCredentialId(e.target.value)} />
      </label>
      <div style={{ marginTop: 8 }}>
        <button onClick={revoke} disabled={!credentialId}>Revoke</button>
      </div>
      {error && (
        <div style={{ marginTop: 16, padding: 12, border: "1px solid #f2b8b5", borderRadius: 8, background: "#fff5f5" }}>
          <p style={{ color: "crimson", margin: 0 }}>{error}</p>
          {(String(error).startsWith("401") || String(error).startsWith("403")) && (
            <p style={{ marginTop: 8, marginBottom: 0 }}>
              You are not authorized. Please <a href="/login">login</a> with scope: <code>credentials:revoke</code>.
            </p>
          )}
        </div>
      )}
      {result && (
        <pre style={{ marginTop: 12, padding: 12, background: "#f6f6f6", overflowX: "auto" }}>
{JSON.stringify(result, null, 2)}
        </pre>
      )}
      <p style={{ marginTop: 16 }}><a href="/">Back</a></p>
    </main>
  );
}
