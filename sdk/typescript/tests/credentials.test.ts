import { describe, it, expect } from "vitest";
import { AgentIdentity } from "../src/identity.js";
import {
  issueVC,
  verifyVC,
  createPresentation,
  verifyPresentation,
} from "../src/credentials.js";

// ── issueVC ───────────────────────────────────────────────────────────────────

describe("issueVC", () => {
  it("returns a three-part JWT string", async () => {
    const issuer = await AgentIdentity.create("issuer");
    const jwt = await issueVC(issuer, "did:key:zSubject123");
    expect(jwt.split(".")).toHaveLength(3);
  });

  it("JWT header has alg=EdDSA and typ=JWT", async () => {
    const issuer = await AgentIdentity.create("issuer");
    const jwt = await issueVC(issuer, "did:key:zSubject123");
    const header = JSON.parse(atob(jwt.split(".")[0].replace(/-/g, "+").replace(/_/g, "/")));
    expect(header.alg).toBe("EdDSA");
    expect(header.typ).toBe("JWT");
  });

  it("JWT payload has iss, sub, jti, iat, vc", async () => {
    const issuer = await AgentIdentity.create("issuer");
    const subject = await AgentIdentity.create("subject");
    const jwt = await issueVC(issuer, subject.did);
    const payload = JSON.parse(atob(jwt.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")));
    expect(payload.iss).toBe(issuer.did);
    expect(payload.sub).toBe(subject.did);
    expect(payload.jti).toMatch(/^urn:uuid:/);
    expect(payload.iat).toBeTypeOf("number");
    expect(payload.vc).toBeTruthy();
  });

  it("includes custom claims in credentialSubject", async () => {
    const issuer = await AgentIdentity.create("issuer");
    const subject = await AgentIdentity.create("subject");
    const jwt = await issueVC(issuer, subject.did, {
      claims: { role: "admin", level: 3 },
    });
    const payload = JSON.parse(atob(jwt.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")));
    expect(payload.vc.credentialSubject.role).toBe("admin");
    expect(payload.vc.credentialSubject.level).toBe(3);
  });

  it("includes custom credential type", async () => {
    const issuer = await AgentIdentity.create("issuer");
    const subject = await AgentIdentity.create("subject");
    const jwt = await issueVC(issuer, subject.did, { credentialType: "TrustCredential" });
    const payload = JSON.parse(atob(jwt.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")));
    expect(payload.vc.type).toContain("TrustCredential");
    expect(payload.vc.type).toContain("VerifiableCredential");
  });

  it("includes exp when ttlSeconds provided", async () => {
    const issuer = await AgentIdentity.create("issuer");
    const subject = await AgentIdentity.create("subject");
    const jwt = await issueVC(issuer, subject.did, { ttlSeconds: 7200 });
    const payload = JSON.parse(atob(jwt.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")));
    expect(payload.exp).toBeGreaterThan(payload.iat);
  });

  it("includes credentialStatus when statusListUrl provided", async () => {
    const issuer = await AgentIdentity.create("issuer");
    const subject = await AgentIdentity.create("subject");
    const jwt = await issueVC(issuer, subject.did, {
      statusListUrl: "https://example.com/status",
      statusListIndex: 42,
    });
    const payload = JSON.parse(atob(jwt.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")));
    expect(payload.vc.credentialStatus).toBeTruthy();
    expect(payload.vc.credentialStatus.statusListIndex).toBe("42");
  });

  it("uses custom credential ID when provided", async () => {
    const issuer = await AgentIdentity.create("issuer");
    const subject = await AgentIdentity.create("subject");
    const jwt = await issueVC(issuer, subject.did, { credentialId: "urn:uuid:custom-id" });
    const payload = JSON.parse(atob(jwt.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")));
    expect(payload.jti).toBe("urn:uuid:custom-id");
  });
});

// ── verifyVC ──────────────────────────────────────────────────────────────────

describe("verifyVC", () => {
  it("verifies a valid VC issued by a did:key issuer", async () => {
    const issuer = await AgentIdentity.create("issuer");
    const subject = await AgentIdentity.create("subject");
    const jwt = await issueVC(issuer, subject.did);
    const result = await verifyVC(jwt);
    expect(result.valid).toBe(true);
    expect(result.issuer).toBe(issuer.did);
    expect(result.subject).toBe(subject.did);
  });

  it("returns credentialType in result", async () => {
    const issuer = await AgentIdentity.create("issuer");
    const subject = await AgentIdentity.create("subject");
    const jwt = await issueVC(issuer, subject.did, { credentialType: "AgentCredential" });
    const result = await verifyVC(jwt);
    expect(result.credentialType).toBe("AgentCredential");
  });

  it("returns custom claims in result.claims", async () => {
    const issuer = await AgentIdentity.create("issuer");
    const subject = await AgentIdentity.create("subject");
    const jwt = await issueVC(issuer, subject.did, { claims: { role: "admin" } });
    const result = await verifyVC(jwt);
    expect(result.valid).toBe(true);
    expect(result.claims?.role).toBe("admin");
  });

  it("fails on tampered JWT", async () => {
    const issuer = await AgentIdentity.create("issuer");
    const subject = await AgentIdentity.create("subject");
    const jwt = await issueVC(issuer, subject.did);
    const parts = jwt.split(".");
    // flip a byte in the signature
    parts[2] = parts[2].slice(0, -4) + "XXXX";
    const result = await verifyVC(parts.join("."));
    expect(result.valid).toBe(false);
  });

  it("fails on expired credential", async () => {
    const issuer = await AgentIdentity.create("issuer");
    const subject = await AgentIdentity.create("subject");
    const jwt = await issueVC(issuer, subject.did, { ttlSeconds: -10 });
    const result = await verifyVC(jwt);
    expect(result.valid).toBe(false);
    expect(result.reason).toContain("expir");
  });

  it("fails when isRevoked returns true", async () => {
    const issuer = await AgentIdentity.create("issuer");
    const subject = await AgentIdentity.create("subject");
    const jwt = await issueVC(issuer, subject.did, { credentialId: "urn:uuid:revoked-id" });
    const result = await verifyVC(jwt, {
      isRevoked: (id) => id === "urn:uuid:revoked-id",
    });
    expect(result.valid).toBe(false);
    expect(result.reason).toContain("revoked");
  });

  it("returns valid when isRevoked returns false", async () => {
    const issuer = await AgentIdentity.create("issuer");
    const subject = await AgentIdentity.create("subject");
    const jwt = await issueVC(issuer, subject.did);
    const result = await verifyVC(jwt, { isRevoked: () => false });
    expect(result.valid).toBe(true);
  });

  it("fails on malformed JWT string", async () => {
    const result = await verifyVC("not.a.jwt.at.all");
    expect(result.valid).toBe(false);
  });

  it("verifies using explicit publicKeyJwk for did:web issuer", async () => {
    const issuer = await AgentIdentity.create("web-issuer", "example.com");
    const subject = await AgentIdentity.create("subject");
    const jwt = await issueVC(issuer, subject.did);
    const result = await verifyVC(jwt, { publicKeyJwk: issuer.publicJwk });
    expect(result.valid).toBe(true);
  });
});

// ── createPresentation / verifyPresentation ────────────────────────────────────

describe("Presentations", () => {
  it("createPresentation returns a three-part JWT", async () => {
    const holder = await AgentIdentity.create("holder");
    const issuer = await AgentIdentity.create("issuer");
    const vc = await issueVC(issuer, holder.did);
    const vp = await createPresentation(holder, [vc]);
    expect(vp.split(".")).toHaveLength(3);
  });

  it("verifyPresentation validates a valid VP", async () => {
    const holder = await AgentIdentity.create("holder");
    const issuer = await AgentIdentity.create("issuer");
    const vc = await issueVC(issuer, holder.did);
    const vp = await createPresentation(holder, [vc]);
    const result = await verifyPresentation(vp);
    expect(result.valid).toBe(true);
    expect(result.holder).toBe(holder.did);
  });

  it("includes audience in VP payload when provided", async () => {
    const holder = await AgentIdentity.create("holder");
    const issuer = await AgentIdentity.create("issuer");
    const vc = await issueVC(issuer, holder.did);
    const vp = await createPresentation(holder, [vc], { audience: "did:key:zVerifier" });
    const payload = JSON.parse(atob(vp.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")));
    expect(payload.aud).toBe("did:key:zVerifier");
  });

  it("verifyPresentation passes with matching expected audience", async () => {
    const holder = await AgentIdentity.create("holder");
    const issuer = await AgentIdentity.create("issuer");
    const vc = await issueVC(issuer, holder.did);
    const vp = await createPresentation(holder, [vc], { audience: "did:key:zVerifier" });
    const result = await verifyPresentation(vp, { expectedAudience: "did:key:zVerifier" });
    expect(result.valid).toBe(true);
    expect(result.audience).toBe("did:key:zVerifier");
  });

  it("verifyPresentation fails with wrong expected audience", async () => {
    const holder = await AgentIdentity.create("holder");
    const issuer = await AgentIdentity.create("issuer");
    const vc = await issueVC(issuer, holder.did);
    const vp = await createPresentation(holder, [vc], { audience: "did:key:zVerifier" });
    const result = await verifyPresentation(vp, { expectedAudience: "did:key:zWrongVerifier" });
    expect(result.valid).toBe(false);
    expect(result.reason?.toLowerCase()).toContain("audience");
  });

  it("verifyPresentation with verifyEmbeddedCredentials validates all VCs", async () => {
    const holder = await AgentIdentity.create("holder");
    const issuer = await AgentIdentity.create("issuer");
    const vc = await issueVC(issuer, holder.did);
    const vp = await createPresentation(holder, [vc]);
    const result = await verifyPresentation(vp, { verifyEmbeddedCredentials: true });
    expect(result.valid).toBe(true);
    expect(result.credentials).toHaveLength(1);
    expect(result.credentials![0].valid).toBe(true);
  });

  it("VP fails with tampered signature", async () => {
    const holder = await AgentIdentity.create("holder");
    const issuer = await AgentIdentity.create("issuer");
    const vc = await issueVC(issuer, holder.did);
    const vp = await createPresentation(holder, [vc]);
    const parts = vp.split(".");
    parts[2] = parts[2].slice(0, -4) + "XXXX";
    const result = await verifyPresentation(parts.join("."));
    expect(result.valid).toBe(false);
  });

  it("VP fails when expired", async () => {
    const holder = await AgentIdentity.create("holder");
    const issuer = await AgentIdentity.create("issuer");
    const vc = await issueVC(issuer, holder.did);
    const vp = await createPresentation(holder, [vc], { ttlSeconds: -5 });
    const result = await verifyPresentation(vp);
    expect(result.valid).toBe(false);
    expect(result.reason).toContain("expir");
  });

  it("VP payload has vp claim with VerifiablePresentation type", async () => {
    const holder = await AgentIdentity.create("holder");
    const issuer = await AgentIdentity.create("issuer");
    const vc = await issueVC(issuer, holder.did);
    const vp = await createPresentation(holder, [vc]);
    const payload = JSON.parse(atob(vp.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")));
    expect(payload.vp).toBeTruthy();
    expect(payload.vp.type).toContain("VerifiablePresentation");
  });
});

// ── Cross-compatibility ───────────────────────────────────────────────────────

describe("Cross-compatibility", () => {
  it("vc claim has W3C context", async () => {
    const issuer = await AgentIdentity.create("issuer");
    const subject = await AgentIdentity.create("subject");
    const jwt = await issueVC(issuer, subject.did);
    const payload = JSON.parse(atob(jwt.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")));
    const ctx = payload.vc["@context"] as string[];
    expect(ctx).toContain("https://www.w3.org/ns/credentials/v2");
  });

  it("credentialSubject.id is the subject DID", async () => {
    const issuer = await AgentIdentity.create("issuer");
    const subject = await AgentIdentity.create("subject");
    const jwt = await issueVC(issuer, subject.did);
    const payload = JSON.parse(atob(jwt.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")));
    expect(payload.vc.credentialSubject.id).toBe(subject.did);
  });
});
