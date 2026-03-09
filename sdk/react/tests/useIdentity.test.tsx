import { describe, it, expect } from "vitest";
import { renderHook, act } from "@testing-library/react";
import { useIdentity } from "../src/useIdentity.js";
import { makeWrapper } from "./helpers.js";

const wrapper = makeWrapper();

describe("useIdentity", () => {
  it("createAgent returns an AgentIdentity with a valid did:key", async () => {
    const { result } = renderHook(() => useIdentity(), { wrapper });

    let agent: Awaited<ReturnType<typeof result.current.createAgent>>;
    await act(async () => {
      agent = await result.current.createAgent("test-agent");
    });

    expect(agent!.did).toMatch(/^did:key:z6Mk/);
    expect(agent!.method).toBe("key");
    expect(agent!.name).toBe("test-agent");
  });

  it("createAgent with domain returns a did:web identity", async () => {
    const { result } = renderHook(() => useIdentity(), { wrapper });

    let agent: Awaited<ReturnType<typeof result.current.createAgent>>;
    await act(async () => {
      agent = await result.current.createAgent("web-agent", "example.com");
    });

    expect(agent!.did).toBe("did:web:example.com");
    expect(agent!.method).toBe("web");
  });

  it("two createAgent calls produce distinct DIDs", async () => {
    const { result } = renderHook(() => useIdentity(), { wrapper });

    let a1: Awaited<ReturnType<typeof result.current.createAgent>>;
    let a2: Awaited<ReturnType<typeof result.current.createAgent>>;
    await act(async () => {
      a1 = await result.current.createAgent("alice");
      a2 = await result.current.createAgent("bob");
    });

    expect(a1!.did).not.toBe(a2!.did);
  });

  it("fromDict round-trips through toDict/fromDict", async () => {
    const { result } = renderHook(() => useIdentity(), { wrapper });

    let original: Awaited<ReturnType<typeof result.current.createAgent>>;
    let restored: Awaited<ReturnType<typeof result.current.fromDict>>;
    await act(async () => {
      original = await result.current.createAgent("round-trip");
      restored = await result.current.fromDict(original.toDict());
    });

    expect(restored!.did).toBe(original!.did);
    expect(restored!.method).toBe(original!.method);
    expect(restored!.privateKeyHex).toBe(original!.privateKeyHex);
  });

  it("resolveDIDKey returns a DID document with matching id", async () => {
    const { result } = renderHook(() => useIdentity(), { wrapper });

    let doc: Record<string, unknown>;
    await act(async () => {
      const agent = await result.current.createAgent("resolver-test");
      doc = await result.current.resolveDIDKey(agent.did);
    });

    expect((doc! as Record<string, unknown>)["id"]).toMatch(/^did:key:/);
    expect(Array.isArray((doc! as Record<string, unknown>)["verificationMethod"])).toBe(true);
  });

  it("resolveDIDKey throws for non-did:key DIDs", async () => {
    const { result } = renderHook(() => useIdentity(), { wrapper });

    await expect(
      act(async () => {
        await result.current.resolveDIDKey("did:web:example.com");
      }),
    ).rejects.toThrow();
  });
});
