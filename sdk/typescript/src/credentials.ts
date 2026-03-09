import {
  SignJWT,
  jwtVerify,
  type JWTPayload,
  type KeyLike,
  importJWK,
} from "jose";
import * as ed from "@noble/ed25519";
import { b58Decode } from "./base58.js";
import type { AgentIdentity } from "./identity.js";

const W3C_VC_CONTEXT = "https://www.w3.org/ns/credentials/v2";
const W3C_VP_CONTEXT = "https://www.w3.org/ns/credentials/v2";

export interface VerificationResult {
  valid: boolean;
  reason?: string;
  claims?: Record<string, unknown>;
  issuer?: string;
  subject?: string;
  credentialType?: string;
}

export interface PresentationResult {
  valid: boolean;
  reason?: string;
  holder?: string;
  audience?: string;
  credentials?: VerificationResult[];
}

// ── helpers ─────────────────────────────────────────────────────────────────

function fail(reason: string): VerificationResult {
  return { valid: false, reason };
}

function pfail(reason: string): PresentationResult {
  return { valid: false, reason };
}

function nowSecs(): number {
  return Math.floor(Date.now() / 1000);
}

function credType(vcPayload: Record<string, unknown>): string {
  const vc = vcPayload["vc"] as Record<string, unknown> | undefined;
  const types = vc?.["type"] as string[] | undefined;
  if (!types) return "VerifiableCredential";
  return types.find((t) => t !== "VerifiableCredential") ?? "VerifiableCredential";
}

async function resolvePublicKey(
  did: string,
  kid: string,
): Promise<KeyLike | Uint8Array> {
  if (did.startsWith("did:key:z")) {
    // Extract public key bytes from did:key multibase
    const multibase = did.split(":")[2];
    const prefixed = b58Decode(multibase.slice(1));
    if (prefixed[0] !== 0xed || prefixed[1] !== 0x01) {
      throw new Error("Only Ed25519 did:key supported");
    }
    const pubBytes = prefixed.slice(2);
    // Return as CryptoKey via JWK
    const b64 = (d: Uint8Array) => {
      let bin = "";
      for (const b of d) bin += String.fromCharCode(b);
      return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    };
    const jwk = { kty: "OKP", crv: "Ed25519", x: b64(pubBytes) };
    return importJWK(jwk, "EdDSA");
  }
  throw new Error(`Cannot resolve public key for DID: ${did}. For did:web, supply verificationMethod manually.`);
}

async function importPublicJwk(jwk: Record<string, string>): Promise<KeyLike> {
  return importJWK(jwk as unknown as Parameters<typeof importJWK>[0], "EdDSA") as Promise<KeyLike>;
}

// ── issueVC ──────────────────────────────────────────────────────────────────

export interface IssueVCOptions {
  credentialType?: string;
  claims?: Record<string, unknown>;
  ttlSeconds?: number;
  credentialId?: string;
  statusListUrl?: string;
  statusListIndex?: number;
}

export async function issueVC(
  issuer: AgentIdentity,
  subjectDid: string,
  opts: IssueVCOptions = {},
): Promise<string> {
  const {
    credentialType = "AgentCredential",
    claims = {},
    ttlSeconds = 3600,
    credentialId,
    statusListUrl,
    statusListIndex,
  } = opts;

  const now = nowSecs();
  const jti = credentialId ?? `urn:uuid:${crypto.randomUUID()}`;

  const credentialSubject: Record<string, unknown> = {
    id: subjectDid,
    ...claims,
  };

  const vcBody: Record<string, unknown> = {
    "@context": [W3C_VC_CONTEXT],
    type: ["VerifiableCredential", credentialType],
    issuer: issuer.did,
    credentialSubject,
  };

  if (statusListUrl && statusListIndex !== undefined) {
    vcBody["credentialStatus"] = {
      id: `${statusListUrl}#${statusListIndex}`,
      type: "BitstringStatusListEntry",
      statusPurpose: "revocation",
      statusListIndex: String(statusListIndex),
      statusListCredential: statusListUrl,
    };
  }

  const payload: JWTPayload & Record<string, unknown> = {
    iss: issuer.did,
    sub: subjectDid,
    jti,
    iat: now,
    vc: vcBody,
  };

  if (ttlSeconds !== null && ttlSeconds !== undefined) {
    payload["exp"] = now + ttlSeconds;
  }

  // Sign using raw private key bytes via @noble/ed25519, wrapped as CryptoKey
  const privateKeyJwk = {
    kty: "OKP",
    crv: "Ed25519",
    x: issuer.publicJwk.x,
    d: btoa(
      String.fromCharCode(...Array.from(await exportPrivateBytes(issuer))),
    )
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, ""),
  };

  const privateKey = await importJWK(privateKeyJwk, "EdDSA");

  return new SignJWT(payload)
    .setProtectedHeader({ alg: "EdDSA", typ: "JWT", kid: issuer.kid })
    .sign(privateKey as KeyLike);
}

/** Extract raw 32-byte private key from AgentIdentity by calling its sign on a known message. */
async function exportPrivateBytes(issuer: AgentIdentity): Promise<Uint8Array> {
  // AgentIdentity exposes privateKeyHex getter
  const hex = (issuer as unknown as { privateKeyHex: string }).privateKeyHex;
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

// ── verifyVC ─────────────────────────────────────────────────────────────────

export interface VerifyVCOptions {
  /** If provided, check the VC is not revoked (subject-supplied lookup function). */
  isRevoked?: (credentialId: string) => Promise<boolean> | boolean;
  /** For did:web issuers that cannot be resolved automatically, supply the verificationMethod. */
  publicKeyJwk?: Record<string, string>;
}

export async function verifyVC(
  jwt: string,
  opts: VerifyVCOptions = {},
): Promise<VerificationResult> {
  try {
    // Decode header to get kid / alg
    const parts = jwt.split(".");
    if (parts.length !== 3) return fail("Not a valid JWT");

    const headerJson = JSON.parse(atob(parts[0].replace(/-/g, "+").replace(/_/g, "/")));
    if (headerJson.alg !== "EdDSA") return fail(`Unsupported algorithm: ${headerJson.alg}`);

    // Decode payload (unverified first to get iss)
    const payloadJson = JSON.parse(
      atob(parts[1].replace(/-/g, "+").replace(/_/g, "/")),
    ) as JWTPayload & Record<string, unknown>;

    const iss = payloadJson["iss"] as string | undefined;
    if (!iss) return fail("Missing iss claim");

    // Resolve public key
    let pubKey: KeyLike | Uint8Array;
    if (opts.publicKeyJwk) {
      pubKey = await importPublicJwk(opts.publicKeyJwk);
    } else {
      try {
        pubKey = await resolvePublicKey(iss, headerJson.kid ?? "");
      } catch (e) {
        return fail(`Cannot resolve public key: ${(e as Error).message}`);
      }
    }

    // Verify signature and claims
    let verified: { payload: JWTPayload };
    try {
      verified = await jwtVerify(jwt, pubKey as KeyLike, { algorithms: ["EdDSA"] });
    } catch (e) {
      const msg = (e as Error).message;
      if (msg.includes('"exp" claim') || msg.includes("expired")) {
        return fail("Credential has expired");
      }
      return fail(`JWT verification failed: ${msg}`);
    }

    const payload = verified.payload as JWTPayload & Record<string, unknown>;

    // Check exp
    const now = nowSecs();
    if (payload["exp"] && (payload["exp"] as number) < now) {
      return fail("Credential has expired");
    }

    // Check vc claim
    const vcClaim = payload["vc"] as Record<string, unknown> | undefined;
    if (!vcClaim) return fail("Missing vc claim");

    const types = vcClaim["type"] as string[] | undefined;
    if (!types?.includes("VerifiableCredential")) {
      return fail("Missing VerifiableCredential type");
    }

    // Revocation check
    const jti = payload["jti"] as string | undefined;
    if (opts.isRevoked && jti) {
      const revoked = await opts.isRevoked(jti);
      if (revoked) return fail("Credential has been revoked");
    }

    const cs = vcClaim["credentialSubject"] as Record<string, unknown> | undefined;
    const { id: _subId, ...extractedClaims } = cs ?? {};

    return {
      valid: true,
      claims: extractedClaims,
      issuer: payload["iss"] as string,
      subject: payload["sub"] as string,
      credentialType: credType(payload),
    };
  } catch (e) {
    return fail(`VC verification error: ${(e as Error).message}`);
  }
}

// ── createPresentation ───────────────────────────────────────────────────────

export interface CreatePresentationOptions {
  audience?: string;
  ttlSeconds?: number;
  presentationId?: string;
  /** If provided, adds a nonce claim to prevent replay attacks. */
  nonce?: string;
}

export async function createPresentation(
  holder: AgentIdentity,
  vcJwts: string[],
  opts: CreatePresentationOptions = {},
): Promise<string> {
  const { audience, ttlSeconds = 300, presentationId, nonce } = opts;

  const now = nowSecs();
  const jti = presentationId ?? `urn:uuid:${crypto.randomUUID()}`;

  const vpBody: Record<string, unknown> = {
    "@context": [W3C_VP_CONTEXT],
    type: ["VerifiablePresentation"],
    verifiableCredential: vcJwts,
  };

  const payload: JWTPayload & Record<string, unknown> = {
    iss: holder.did,
    jti,
    iat: now,
    vp: vpBody,
  };

  if (audience) payload["aud"] = audience;
  if (nonce) payload["nonce"] = nonce;
  if (ttlSeconds !== null && ttlSeconds !== undefined) {
    payload["exp"] = now + ttlSeconds;
  }

  const privateKeyJwk = {
    kty: "OKP",
    crv: "Ed25519",
    x: holder.publicJwk.x,
    d: btoa(
      String.fromCharCode(...Array.from(await exportPrivateBytes(holder))),
    )
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, ""),
  };

  const privateKey = await importJWK(privateKeyJwk, "EdDSA");

  return new SignJWT(payload)
    .setProtectedHeader({ alg: "EdDSA", typ: "JWT", kid: holder.kid })
    .sign(privateKey as KeyLike);
}

// ── verifyPresentation ───────────────────────────────────────────────────────

export interface VerifyPresentationOptions {
  expectedAudience?: string;
  /** If provided, the nonce claim must match exactly to prevent replay attacks. */
  expectedNonce?: string;
  /** If provided, each embedded VC is also fully verified. */
  verifyEmbeddedCredentials?: boolean;
}

export async function verifyPresentation(
  vpJwt: string,
  opts: VerifyPresentationOptions = {},
): Promise<PresentationResult> {
  try {
    const parts = vpJwt.split(".");
    if (parts.length !== 3) return pfail("Not a valid JWT");

    const headerJson = JSON.parse(atob(parts[0].replace(/-/g, "+").replace(/_/g, "/")));
    if (headerJson.alg !== "EdDSA") return pfail(`Unsupported algorithm: ${headerJson.alg}`);

    const payloadJson = JSON.parse(
      atob(parts[1].replace(/-/g, "+").replace(/_/g, "/")),
    ) as JWTPayload & Record<string, unknown>;

    const iss = payloadJson["iss"] as string | undefined;
    if (!iss) return pfail("Missing iss claim");

    let pubKey: KeyLike | Uint8Array;
    try {
      pubKey = await resolvePublicKey(iss, headerJson.kid ?? "");
    } catch (e) {
      return pfail(`Cannot resolve holder public key: ${(e as Error).message}`);
    }

    // Build verify options — only check audience if expected was provided
    const verifyOpts: Parameters<typeof jwtVerify>[2] = { algorithms: ["EdDSA"] };
    if (opts.expectedAudience) {
      verifyOpts.audience = opts.expectedAudience;
    }

    let verified: { payload: JWTPayload };
    try {
      verified = await jwtVerify(vpJwt, pubKey as KeyLike, verifyOpts);
    } catch (e) {
      const msg = (e as Error).message;
      if (msg.includes("audience") || msg.includes('"aud"')) return pfail("Audience mismatch");
      if (msg.includes('"exp" claim') || msg.includes("expired")) return pfail("Presentation has expired");
      return pfail(`VP JWT verification failed: ${msg}`);
    }

    const payload = verified.payload as JWTPayload & Record<string, unknown>;

    const now = nowSecs();
    if (payload["exp"] && (payload["exp"] as number) < now) {
      return pfail("Presentation has expired");
    }

    // Nonce validation — prevents replay attacks
    if (opts.expectedNonce !== undefined) {
      const actualNonce = payload["nonce"] as string | undefined;
      if (actualNonce !== opts.expectedNonce) {
        return pfail(`Nonce mismatch: expected '${opts.expectedNonce}', got '${actualNonce}'`);
      }
    }

    const vpClaim = payload["vp"] as Record<string, unknown> | undefined;
    if (!vpClaim) return pfail("Missing vp claim");

    const types = vpClaim["type"] as string[] | undefined;
    if (!types?.includes("VerifiablePresentation")) {
      return pfail("Missing VerifiablePresentation type");
    }

    const vcJwts = (vpClaim["verifiableCredential"] as string[] | undefined) ?? [];

    // Verify embedded credentials
    let credResults: VerificationResult[] | undefined;
    if (opts.verifyEmbeddedCredentials) {
      credResults = await Promise.all(vcJwts.map((vc) => verifyVC(vc)));
      const allValid = credResults.every((r) => r.valid);
      if (!allValid) {
        const first = credResults.find((r) => !r.valid);
        return pfail(`Embedded credential invalid: ${first?.reason}`);
      }
    }

    const audClaim = payload["aud"];
    const audience = Array.isArray(audClaim) ? audClaim[0] : (audClaim as string | undefined);

    return {
      valid: true,
      holder: iss,
      audience,
      credentials: credResults,
    };
  } catch (e) {
    return pfail(`VP verification error: ${(e as Error).message}`);
  }
}
