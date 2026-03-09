import * as ed from "@noble/ed25519";
import { b58Encode, b58Decode } from "./base58.js";

// Multicodec prefix for Ed25519 public key (varint 0xed01)
const ED25519_MULTICODEC_PREFIX = new Uint8Array([0xed, 0x01]);

function b64url(data: Uint8Array): string {
  let bin = "";
  for (const b of data) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function pubKeyToDidKey(pubBytes: Uint8Array): string {
  const prefixed = new Uint8Array(ED25519_MULTICODEC_PREFIX.length + pubBytes.length);
  prefixed.set(ED25519_MULTICODEC_PREFIX);
  prefixed.set(pubBytes, ED25519_MULTICODEC_PREFIX.length);
  return `did:key:z${b58Encode(prefixed)}`;
}

function pubKeyToMultibase(pubBytes: Uint8Array): string {
  const prefixed = new Uint8Array(ED25519_MULTICODEC_PREFIX.length + pubBytes.length);
  prefixed.set(ED25519_MULTICODEC_PREFIX);
  prefixed.set(pubBytes, ED25519_MULTICODEC_PREFIX.length);
  return `z${b58Encode(prefixed)}`;
}

function buildDidKeyDocument(did: string, pubBytes: Uint8Array, kid: string): Record<string, unknown> {
  const multibase = pubKeyToMultibase(pubBytes);
  return {
    "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/ed25519-2020/v1"],
    id: did,
    verificationMethod: [
      {
        id: kid,
        type: "Ed25519VerificationKey2020",
        controller: did,
        publicKeyMultibase: multibase,
      },
    ],
    authentication: [kid],
    assertionMethod: [kid],
    capabilityInvocation: [kid],
    capabilityDelegation: [kid],
  };
}

function buildDidWebDocument(did: string, pubBytes: Uint8Array, kid: string): Record<string, unknown> {
  return {
    "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/ed25519-2020/v1"],
    id: did,
    verificationMethod: [
      {
        id: kid,
        type: "JsonWebKey2020",
        controller: did,
        publicKeyJwk: {
          kty: "OKP",
          crv: "Ed25519",
          x: b64url(pubBytes),
        },
      },
    ],
    authentication: [kid],
    assertionMethod: [kid],
    capabilityInvocation: [kid],
    capabilityDelegation: [kid],
  };
}

export interface AgentIdentityDict {
  did: string;
  method: string;
  name: string;
  domain?: string;
  privateKeyHex: string;
  publicKeyHex: string;
  publicJwk: Record<string, string>;
  kid: string;
}

export class AgentIdentity {
  readonly did: string;
  readonly method: "key" | "web";
  readonly publicJwk: Record<string, string>;
  readonly kid: string;

  private readonly _privateKeyBytes: Uint8Array;
  private readonly _publicKeyBytes: Uint8Array;
  private readonly _name: string;
  private readonly _domain?: string;

  private constructor(
    did: string,
    method: "key" | "web",
    privateKeyBytes: Uint8Array,
    publicKeyBytes: Uint8Array,
    publicJwk: Record<string, string>,
    kid: string,
    name: string,
    domain?: string,
  ) {
    this.did = did;
    this.method = method;
    this._privateKeyBytes = privateKeyBytes;
    this._publicKeyBytes = publicKeyBytes;
    this.publicJwk = publicJwk;
    this.kid = kid;
    this._name = name;
    this._domain = domain;
  }

  static async create(name: string, domain?: string): Promise<AgentIdentity> {
    const privateKeyBytes = ed.utils.randomPrivateKey();
    const publicKeyBytes = await ed.getPublicKeyAsync(privateKeyBytes);
    return AgentIdentity._fromRaw(name, domain, privateKeyBytes, publicKeyBytes);
  }

  static async fromPrivateKeyHex(hex: string, name: string, domain?: string): Promise<AgentIdentity> {
    const privateKeyBytes = hexToBytes(hex);
    const publicKeyBytes = await ed.getPublicKeyAsync(privateKeyBytes);
    return AgentIdentity._fromRaw(name, domain, privateKeyBytes, publicKeyBytes);
  }

  private static _fromRaw(
    name: string,
    domain: string | undefined,
    privateKeyBytes: Uint8Array,
    publicKeyBytes: Uint8Array,
  ): AgentIdentity {
    let did: string;
    let method: "key" | "web";
    let kid: string;

    if (domain) {
      method = "web";
      did = `did:web:${domain}`;
      kid = `${did}#key-1`;
    } else {
      method = "key";
      did = pubKeyToDidKey(publicKeyBytes);
      kid = `${did}#${did.split(":")[2]}`;
    }

    const publicJwk: Record<string, string> = {
      kty: "OKP",
      crv: "Ed25519",
      x: b64url(publicKeyBytes),
    };

    return new AgentIdentity(did, method, privateKeyBytes, publicKeyBytes, publicJwk, kid, name, domain);
  }

  get name(): string {
    return this._name;
  }

  get domain(): string | undefined {
    return this._domain;
  }

  get publicKeyBytes(): Uint8Array {
    return this._publicKeyBytes;
  }

  get privateKeyHex(): string {
    return bytesToHex(this._privateKeyBytes);
  }

  get didDocument(): Record<string, unknown> {
    if (this.method === "web") {
      return buildDidWebDocument(this.did, this._publicKeyBytes, this.kid);
    }
    return buildDidKeyDocument(this.did, this._publicKeyBytes, this.kid);
  }

  async sign(message: Uint8Array): Promise<Uint8Array> {
    return ed.signAsync(message, this._privateKeyBytes);
  }

  async verify(message: Uint8Array, signature: Uint8Array): Promise<boolean> {
    return ed.verifyAsync(signature, message, this._publicKeyBytes);
  }

  toDict(): AgentIdentityDict {
    return {
      did: this.did,
      method: this.method,
      name: this._name,
      domain: this._domain,
      privateKeyHex: this.privateKeyHex,
      publicKeyHex: bytesToHex(this._publicKeyBytes),
      publicJwk: this.publicJwk,
      kid: this.kid,
    };
  }

  static async fromDict(d: AgentIdentityDict): Promise<AgentIdentity> {
    return AgentIdentity.fromPrivateKeyHex(d.privateKeyHex, d.name, d.domain);
  }
}

export async function resolveDIDKey(did: string): Promise<Record<string, unknown>> {
  if (!did.startsWith("did:key:z")) {
    throw new Error(`Not a did:key DID: ${did}`);
  }
  const multibase = did.split(":")[2];
  const prefixed = b58Decode(multibase.slice(1)); // strip 'z'

  if (prefixed[0] !== 0xed || prefixed[1] !== 0x01) {
    throw new Error("Only Ed25519 did:key DIDs are supported");
  }
  const pubBytes = prefixed.slice(2);
  const kid = `${did}#${multibase}`;
  return buildDidKeyDocument(did, pubBytes, kid);
}

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error("Invalid hex string");
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
