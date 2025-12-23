export class PramanaClient {
  baseUrl: string;

  constructor(baseUrl = "http://localhost:8000") {
    this.baseUrl = baseUrl;
  }

  async createAgent(name: string) {
    return this.post("/v1/agents", { name });
  }

  async issueCredential(params: {
    issuer_agent_id: string;
    subject_did: string;
    credential_type?: string;
    ttl_seconds?: number;
    subject_claims?: Record<string, unknown>;
  }) {
    return this.post("/v1/credentials/issue", {
      credential_type: "AgentCredential",
      ...params,
    });
  }

  async verifyCredential(jwt: string) {
    return this.post("/v1/credentials/verify", { jwt });
  }

  async revokeCredential(credentialId: string) {
    return this.post(`/v1/credentials/${credentialId}/revoke`, {});
  }

  private async post(path: string, body: unknown) {
    const res = await fetch(this.baseUrl + path, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      const text = await res.text();
      throw new Error(`${res.status} ${res.statusText}: ${text}`);
    }
    return res.json();
  }
}
