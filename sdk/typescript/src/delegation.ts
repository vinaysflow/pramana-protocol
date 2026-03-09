import { SignJWT, jwtVerify, type JWTPayload, importJWK, type KeyLike } from "jose";
import { b58Decode } from "./base58.js";
import type { AgentIdentity } from "./identity.js";

// Maximum absolute chain recursion guard (not configurable per-credential)
const ABSOLUTE_MAX_CHAIN_DEPTH = 10;

// ── Scope types ───────────────────────────────────────────────────────────────

export interface Scope {
  actions?: string[];
  maxAmount?: number;
  currency?: string;
  merchants?: string[];
  categories?: string[];
  constraints?: Record<string, unknown>;
}

// ── Errors ───────────────────────────────────────────────────────────────────

export class ScopeEscalationError extends Error {
  readonly field: string;
  readonly parentValue: unknown;
  readonly childValue: unknown;

  constructor(field: string, parentValue: unknown, childValue: unknown) {
    super(
      `Scope escalation on '${field}': child value ${JSON.stringify(childValue)} exceeds parent ${JSON.stringify(parentValue)}`,
    );
    this.name = "ScopeEscalationError";
    this.field = field;
    this.parentValue = parentValue;
    this.childValue = childValue;
  }
}

// ── Result type ───────────────────────────────────────────────────────────────

export interface DelegationResult {
  valid: boolean;
  reason?: string;
  delegator?: string;
  delegate?: string;
  scope?: Scope;
  depth?: number;
}

// ── Scope intersection ────────────────────────────────────────────────────────

export function intersectScopes(parent: Scope, child: Scope): Scope {
  const result: Scope = {};

  // actions: intersection of sets; if child doesn't specify, inherit parent
  if (parent.actions !== undefined && child.actions !== undefined) {
    result.actions = parent.actions.filter((a) => child.actions!.includes(a));
  } else if (parent.actions !== undefined) {
    result.actions = [...parent.actions];
  } else if (child.actions !== undefined) {
    result.actions = [...child.actions];
  }

  // maxAmount: minimum of both
  if (parent.maxAmount !== undefined && child.maxAmount !== undefined) {
    result.maxAmount = Math.min(parent.maxAmount, child.maxAmount);
  } else if (parent.maxAmount !== undefined) {
    result.maxAmount = parent.maxAmount;
  } else if (child.maxAmount !== undefined) {
    result.maxAmount = child.maxAmount;
  }

  // currency: must match if both set; child cannot change currency
  if (parent.currency !== undefined && child.currency !== undefined) {
    if (parent.currency !== child.currency) {
      throw new ScopeEscalationError("currency", parent.currency, child.currency);
    }
    result.currency = parent.currency;
  } else if (parent.currency !== undefined) {
    result.currency = parent.currency;
  } else if (child.currency !== undefined) {
    result.currency = child.currency;
  }

  // merchants: wildcard ["*"] handling matching Python SDK
  const pm = parent.merchants;
  const cm = child.merchants;
  if (pm !== undefined && cm !== undefined) {
    const parentWild = pm.length === 1 && pm[0] === "*";
    const childWild = cm.length === 1 && cm[0] === "*";
    if (parentWild && childWild) {
      result.merchants = ["*"];
    } else if (parentWild) {
      result.merchants = [...cm];
    } else if (childWild) {
      result.merchants = [...pm];
    } else {
      // child must be subset of parent
      const invalid = cm.filter((m) => !pm.includes(m));
      if (invalid.length > 0) {
        throw new ScopeEscalationError("merchants", pm, cm);
      }
      result.merchants = [...cm];
    }
  } else if (pm !== undefined) {
    result.merchants = [...pm];
  } else if (cm !== undefined) {
    result.merchants = [...cm];
  }

  // categories: must be subset of parent
  if (parent.categories !== undefined && child.categories !== undefined) {
    const invalid = child.categories.filter((c) => !parent.categories!.includes(c));
    if (invalid.length > 0) {
      throw new ScopeEscalationError("categories", parent.categories, child.categories);
    }
    result.categories = [...child.categories];
  } else if (parent.categories !== undefined) {
    result.categories = [...parent.categories];
  } else if (child.categories !== undefined) {
    result.categories = [...child.categories];
  }

  // constraints: child overrides parent (matching Python {**parent, **child})
  if (parent.constraints !== undefined || child.constraints !== undefined) {
    result.constraints = {
      ...(parent.constraints ?? {}),
      ...(child.constraints ?? {}),
    };
  }

  return result;
}

export function validateScopeNarrowing(parent: Scope, child: Scope): void {
  // Run intersection — throws ScopeEscalationError on any violation
  intersectScopes(parent, child);

  // Explicit checks for clear error messages
  if (parent.maxAmount !== undefined && child.maxAmount !== undefined) {
    if (child.maxAmount > parent.maxAmount) {
      throw new ScopeEscalationError("maxAmount", parent.maxAmount, child.maxAmount);
    }
  }
  if (parent.actions !== undefined && child.actions !== undefined) {
    const escalated = child.actions.filter((a) => !parent.actions!.includes(a));
    if (escalated.length > 0) {
      throw new ScopeEscalationError("actions", parent.actions, child.actions);
    }
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function nowSecs(): number {
  return Math.floor(Date.now() / 1000);
}

async function exportPrivateBytes(issuer: AgentIdentity): Promise<Uint8Array> {
  return (issuer as unknown as { _privateKeyBytes: Uint8Array })._privateKeyBytes;
}

async function getPrivateJwk(issuer: AgentIdentity) {
  const bytes = await exportPrivateBytes(issuer);
  const d = btoa(String.fromCharCode(...Array.from(bytes)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  return {
    kty: "OKP",
    crv: "Ed25519",
    x: issuer.publicJwk.x,
    d,
  };
}

async function resolvePublicKeyForDid(did: string): Promise<KeyLike> {
  if (!did.startsWith("did:key:z")) {
    throw new Error(`Cannot resolve public key for DID: ${did}`);
  }
  const multibase = did.split(":")[2];
  const prefixed = b58Decode(multibase.slice(1));
  if (prefixed[0] !== 0xed || prefixed[1] !== 0x01) {
    throw new Error("Only Ed25519 did:key supported");
  }
  const pubBytes = prefixed.slice(2);
  const b64 = (d: Uint8Array) => {
    let bin = "";
    for (const b of d) bin += String.fromCharCode(b);
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  };
  const jwk = { kty: "OKP", crv: "Ed25519", x: b64(pubBytes) };
  return importJWK(jwk, "EdDSA") as Promise<KeyLike>;
}

// ── W3C VC context ────────────────────────────────────────────────────────────

const W3C_VC_CONTEXT = "https://www.w3.org/ns/credentials/v2";

// ── DelegationCredential claims extracted from VC payload ─────────────────────

interface DelegationClaims {
  delegatedBy: string;
  delegationScope: Scope;
  delegationDepth: number;
  maxDelegationDepth: number;
  parentDelegation?: string | null;
}

function extractDelegationClaims(
  vcPayload: Record<string, unknown>,
): DelegationClaims | null {
  // Support both:
  //   1. W3C VC format: payload.vc.credentialSubject (new aligned format)
  //   2. Legacy flat del claim (for backwards compat during migration)
  const vc = vcPayload["vc"] as Record<string, unknown> | undefined;
  if (vc) {
    const cs = vc["credentialSubject"] as Record<string, unknown> | undefined;
    if (cs) {
      return {
        delegatedBy: (cs["delegatedBy"] as string) ?? (vcPayload["iss"] as string),
        delegationScope: (cs["delegationScope"] as Scope) ?? {},
        delegationDepth: (cs["delegationDepth"] as number) ?? 0,
        maxDelegationDepth: (cs["maxDelegationDepth"] as number) ?? ABSOLUTE_MAX_CHAIN_DEPTH,
        parentDelegation: (cs["parentDelegation"] as string | null) ?? null,
      };
    }
  }
  // Legacy del claim (old TS format — kept for backwards compat)
  const del = vcPayload["del"] as
    | { scope: Scope; depth: number; parentJti: string | null }
    | undefined;
  if (del) {
    return {
      delegatedBy: vcPayload["iss"] as string,
      delegationScope: del.scope,
      delegationDepth: del.depth,
      maxDelegationDepth: ABSOLUTE_MAX_CHAIN_DEPTH,
      parentDelegation: null, // legacy format doesn't embed parent JWT
    };
  }
  return null;
}

// ── issueDelegation ───────────────────────────────────────────────────────────

export interface IssueDelegationOptions {
  ttlSeconds?: number;
  delegationId?: string;
  /** Maximum depth that sub-delegates may further delegate. Default 1. */
  maxDepth?: number;
  /** Optional: link to a BitstringStatusList for revocation. */
  statusListUrl?: string;
  statusListIndex?: number;
}

export async function issueDelegation(
  issuer: AgentIdentity,
  delegateDid: string,
  scope: Scope,
  opts: IssueDelegationOptions = {},
): Promise<string> {
  const { ttlSeconds = 3600, delegationId, maxDepth = 1 } = opts;
  const now = nowSecs();
  const jti = delegationId ?? `urn:uuid:${crypto.randomUUID()}`;

  const credentialSubject: Record<string, unknown> = {
    id: delegateDid,
    delegatedBy: issuer.did,
    delegationScope: scope,
    delegationDepth: 0,
    maxDelegationDepth: maxDepth,
  };

  const vcBody: Record<string, unknown> = {
    "@context": [W3C_VC_CONTEXT],
    type: ["VerifiableCredential", "DelegationCredential"],
    issuer: issuer.did,
    validFrom: new Date(now * 1000).toISOString(),
    credentialSubject,
  };

  // Optional revocation support
  if (opts.statusListUrl !== undefined && opts.statusListIndex !== undefined) {
    vcBody["credentialStatus"] = {
      id: `${opts.statusListUrl}#${opts.statusListIndex}`,
      type: "BitstringStatusListEntry",
      statusPurpose: "revocation",
      statusListIndex: String(opts.statusListIndex),
      statusListCredential: opts.statusListUrl,
    };
  }

  const payload: JWTPayload & Record<string, unknown> = {
    iss: issuer.did,
    sub: delegateDid,
    jti,
    iat: now,
    vc: vcBody,
  };

  if (ttlSeconds !== null && ttlSeconds !== undefined) {
    payload["exp"] = now + ttlSeconds;
  }

  const privateKey = await importJWK(await getPrivateJwk(issuer), "EdDSA");

  return new SignJWT(payload)
    .setProtectedHeader({ alg: "EdDSA", typ: "JWT", kid: issuer.kid })
    .sign(privateKey as KeyLike);
}

// ── delegateFurther ───────────────────────────────────────────────────────────

export interface DelegateFurtherOptions {
  ttlSeconds?: number;
  delegationId?: string;
  /** Optional: link to a BitstringStatusList for revocation. */
  statusListUrl?: string;
  statusListIndex?: number;
}

export async function delegateFurther(
  currentHolder: AgentIdentity,
  parentDelegationJwt: string,
  newDelegateDid: string,
  requestedScope: Scope,
  opts: DelegateFurtherOptions = {},
): Promise<string> {
  const { ttlSeconds = 3600, delegationId } = opts;

  // Decode parent without verification first to get iss
  const parts = parentDelegationJwt.split(".");
  if (parts.length !== 3) throw new Error("Invalid parent delegation JWT");

  const parentPayload = JSON.parse(
    atob(parts[1].replace(/-/g, "+").replace(/_/g, "/")),
  ) as JWTPayload & Record<string, unknown>;

  // Verify parent signature
  const parentIss = parentPayload["iss"] as string;
  const parentPubKey = await resolvePublicKeyForDid(parentIss);

  try {
    await jwtVerify(parentDelegationJwt, parentPubKey, { algorithms: ["EdDSA"] });
  } catch (e) {
    throw new Error(`Parent delegation invalid: ${(e as Error).message}`);
  }

  // Check parent not expired
  const now = nowSecs();
  if (parentPayload["exp"] && (parentPayload["exp"] as number) < now) {
    throw new Error("Parent delegation has expired");
  }

  // Check that currentHolder is the subject of the parent
  if (parentPayload["sub"] !== currentHolder.did) {
    throw new Error("currentHolder is not the subject of the parent delegation");
  }

  // Extract delegation claims (supports both new VC format and legacy del format)
  const parentClaims = extractDelegationClaims(parentPayload);
  if (!parentClaims) {
    throw new Error("Parent delegation JWT missing credentialSubject / del claim");
  }

  const newDepth = parentClaims.delegationDepth + 1;
  if (newDepth > parentClaims.maxDelegationDepth) {
    throw new Error(
      `Delegation depth ${newDepth} exceeds maximum ${parentClaims.maxDelegationDepth}`,
    );
  }
  if (newDepth >= ABSOLUTE_MAX_CHAIN_DEPTH) {
    throw new Error(`Delegation depth exceeds absolute maximum of ${ABSOLUTE_MAX_CHAIN_DEPTH}`);
  }

  // Scope narrowing — throws ScopeEscalationError if child exceeds parent
  const narrowedScope = intersectScopes(parentClaims.delegationScope, requestedScope);

  const jti = delegationId ?? `urn:uuid:${crypto.randomUUID()}`;

  // Parent-bound TTL: child cannot outlive parent
  const parentExp = parentPayload["exp"] as number | undefined;
  let childExp = now + ttlSeconds;
  if (parentExp !== undefined && childExp > parentExp) {
    childExp = parentExp;
  }

  const credentialSubject: Record<string, unknown> = {
    id: newDelegateDid,
    delegatedBy: currentHolder.did,
    delegationScope: narrowedScope,
    delegationDepth: newDepth,
    maxDelegationDepth: parentClaims.maxDelegationDepth,
    parentDelegation: parentDelegationJwt,
  };

  const vcBody: Record<string, unknown> = {
    "@context": [W3C_VC_CONTEXT],
    type: ["VerifiableCredential", "DelegationCredential"],
    issuer: currentHolder.did,
    validFrom: new Date(now * 1000).toISOString(),
    credentialSubject,
  };

  // Optional revocation support
  if (opts.statusListUrl !== undefined && opts.statusListIndex !== undefined) {
    vcBody["credentialStatus"] = {
      id: `${opts.statusListUrl}#${opts.statusListIndex}`,
      type: "BitstringStatusListEntry",
      statusPurpose: "revocation",
      statusListIndex: String(opts.statusListIndex),
      statusListCredential: opts.statusListUrl,
    };
  }

  const payload: JWTPayload & Record<string, unknown> = {
    iss: currentHolder.did,
    sub: newDelegateDid,
    jti,
    iat: now,
    exp: childExp,
    vc: vcBody,
  };

  const privateKey = await importJWK(await getPrivateJwk(currentHolder), "EdDSA");

  return new SignJWT(payload)
    .setProtectedHeader({ alg: "EdDSA", typ: "JWT", kid: currentHolder.kid })
    .sign(privateKey as KeyLike);
}

// ── verifyDelegationChain ─────────────────────────────────────────────────────

export interface VerifyDelegationChainOptions {
  requiredAction?: string;
}

export async function verifyDelegationChain(
  delegationJwts: string[],
  opts: VerifyDelegationChainOptions = {},
): Promise<DelegationResult> {
  if (!delegationJwts || delegationJwts.length === 0) {
    return { valid: false, reason: "Empty delegation chain" };
  }

  if (delegationJwts.length > ABSOLUTE_MAX_CHAIN_DEPTH) {
    return { valid: false, reason: "Chain exceeds maximum depth" };
  }

  try {
    let lastScope: Scope = {};
    let lastSub: string | undefined;

    for (let i = 0; i < delegationJwts.length; i++) {
      const jwt = delegationJwts[i];
      const parts = jwt.split(".");
      if (parts.length !== 3) return { valid: false, reason: `JWT ${i} is malformed` };

      const payload = JSON.parse(
        atob(parts[1].replace(/-/g, "+").replace(/_/g, "/")),
      ) as JWTPayload & Record<string, unknown>;

      const iss = payload["iss"] as string;

      // Verify signature
      let pubKey: KeyLike;
      try {
        pubKey = await resolvePublicKeyForDid(iss);
      } catch (e) {
        return {
          valid: false,
          reason: `Cannot resolve key for ${iss}: ${(e as Error).message}`,
        };
      }

      try {
        await jwtVerify(jwt, pubKey, { algorithms: ["EdDSA"] });
      } catch (e) {
        const msg = (e as Error).message;
        if (msg.includes('"exp" claim') || msg.includes("expired")) {
          return { valid: false, reason: `JWT ${i} has expired` };
        }
        return { valid: false, reason: `JWT ${i} signature invalid: ${msg}` };
      }

      // Check expiry
      const now = nowSecs();
      if (payload["exp"] && (payload["exp"] as number) < now) {
        return { valid: false, reason: `JWT ${i} has expired` };
      }

      // Extract delegation claims (supports new VC format and legacy del)
      const claims = extractDelegationClaims(payload);
      if (!claims) {
        return { valid: false, reason: `JWT ${i} missing delegation claims (vc.credentialSubject or del)` };
      }

      // Chain continuity: issuer of current must be subject of previous
      if (i > 0 && iss !== lastSub) {
        return {
          valid: false,
          reason: `Chain broken at position ${i}: issuer ${iss} != previous subject ${lastSub}`,
        };
      }

      // Scope narrowing check (only for non-root links)
      if (i > 0) {
        try {
          lastScope = intersectScopes(lastScope, claims.delegationScope);
        } catch (e) {
          return { valid: false, reason: `Scope escalation at position ${i}: ${(e as Error).message}` };
        }
      } else {
        lastScope = claims.delegationScope;
      }

      lastSub = payload["sub"] as string;
    }

    // Check required action if specified
    if (opts.requiredAction && lastScope.actions) {
      if (!lastScope.actions.includes(opts.requiredAction)) {
        return {
          valid: false,
          reason: `Required action '${opts.requiredAction}' not in scope actions: ${lastScope.actions.join(", ")}`,
        };
      }
    }

    const firstPayload = JSON.parse(
      atob(delegationJwts[0].split(".")[1].replace(/-/g, "+").replace(/_/g, "/")),
    ) as JWTPayload & Record<string, unknown>;

    return {
      valid: true,
      delegator: firstPayload["iss"] as string,
      delegate: lastSub,
      scope: lastScope,
      depth: delegationJwts.length - 1,
    };
  } catch (e) {
    return { valid: false, reason: `Verification error: ${(e as Error).message}` };
  }
}
