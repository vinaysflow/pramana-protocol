"use client";

import { useState } from "react";
import { apiPost } from "../../lib/api";

export default function VerifyPage() {
  const [jwt, setJwt] = useState("");
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState("");

  async function verify() {
    setError("");
    setResult(null);
    try {
      const resp = await apiPost<any>("/v1/credentials/verify", { jwt });
      setResult(resp);
    } catch (e: any) {
      setError(String(e?.message || e));
    }
  }

  return (
    <main style={{ maxWidth: 900 }}>
      <h1>Verify</h1>
      <textarea style={{ width: "100%", height: 200 }} value={jwt} onChange={(e) => setJwt(e.target.value)} />
      <div style={{ marginTop: 8 }}>
        <button onClick={verify}>Verify</button>
      </div>
      {error && <p style={{ color: "crimson" }}>{error}</p>}
      {result && (
        <pre style={{ marginTop: 12, padding: 12, background: "#f6f6f6", overflowX: "auto" }}>
{JSON.stringify(result, null, 2)}
        </pre>
      )}
      <p style={{ marginTop: 16 }}><a href="/">Back</a></p>
    </main>
  );
}
