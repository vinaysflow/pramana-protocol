"use client";

import { useState } from "react";
import { apiPost } from "../../lib/api";

type CreateAgentResp = {
  id: string;
  name: string;
  did: string;
  did_document_url: string;
};

type IssueResp = {
  credential_id: string;
  jwt: string;
  jti: string;
  status_list_id: string;
  status_list_index: number;
};

export default function IssuePage() {
  const [agentName, setAgentName] = useState("issuer-1");
  const [issuer, setIssuer] = useState<CreateAgentResp | null>(null);

  const [subjectDid, setSubjectDid] = useState("did:web:example.com:subject:123");
  const [credentialType, setCredentialType] = useState("AgentCredential");
  const [jwt, setJwt] = useState<string>("");
  const [credId, setCredId] = useState<string>("");

  const [error, setError] = useState<string>("");

  async function createAgent() {
    setError("");
    const resp = await apiPost<CreateAgentResp>("/v1/agents", { name: agentName });
    setIssuer(resp);
  }

  async function issue() {
    setError("");
    if (!issuer) throw new Error("Create issuer first");
    const resp = await apiPost<IssueResp>("/v1/credentials/issue", {
      issuer_agent_id: issuer.id,
      subject_did: subjectDid,
      credential_type: credentialType,
    });
    setJwt(resp.jwt);
    setCredId(resp.credential_id);
  }

  return (
    <main style={{ maxWidth: 900 }}>
      <h1>Issue</h1>

      <section style={{ padding: 12, border: "1px solid #ddd", borderRadius: 8, marginBottom: 16 }}>
        <h2>Create issuer</h2>
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          <input value={agentName} onChange={(e) => setAgentName(e.target.value)} />
          <button onClick={createAgent}>Create</button>
        </div>
        {issuer && (
          <div style={{ marginTop: 8 }}>
            <div><b>issuer_agent_id</b>: {issuer.id}</div>
            <div><b>did</b>: {issuer.did}</div>
            <div><b>did_document_url</b>: {issuer.did_document_url}</div>
          </div>
        )}
      </section>

      <section style={{ padding: 12, border: "1px solid #ddd", borderRadius: 8 }}>
        <h2>Issue credential</h2>
        <div style={{ display: "grid", gap: 8 }}>
          <label>
            Subject DID
            <input style={{ width: "100%" }} value={subjectDid} onChange={(e) => setSubjectDid(e.target.value)} />
          </label>
          <label>
            Credential type
            <input style={{ width: "100%" }} value={credentialType} onChange={(e) => setCredentialType(e.target.value)} />
          </label>
          <button disabled={!issuer} onClick={issue}>Issue</button>
        </div>

        {credId && (
          <div style={{ marginTop: 12 }}>
            <div><b>credential_id</b>: {credId}</div>
            <div style={{ marginTop: 8 }}>
              <b>jwt</b>
              <textarea style={{ width: "100%", height: 200 }} value={jwt} readOnly />
            </div>
          </div>
        )}
      </section>

      {error && (
        <div style={{ marginTop: 16, padding: 12, border: "1px solid #f2b8b5", borderRadius: 8, background: "#fff5f5" }}>
          <p style={{ color: "crimson", margin: 0 }}>{error}</p>
          {(String(error).startsWith("401") || String(error).startsWith("403")) && (
            <p style={{ marginTop: 8, marginBottom: 0 }}>
              You are not authorized. Please <a href="/login">login</a> (Keycloak) with scopes: <code>agents:create</code>, <code>credentials:issue</code>.
            </p>
          )}
        </div>
      )}

      <p style={{ marginTop: 16 }}><a href="/">Back</a></p>
    </main>
  );
}
