// Step execution engine — pure async logic, no React.
// Takes a scenario definition and a set of callbacks to update UI state.

import { ScenarioDef, StepDef, RunContext } from "./scenarios";
import { apiBase, getAccessToken } from "../../lib/api";

export interface StepResult {
  stepId: string;
  status: "success" | "failure" | "expected-failure";
  request?: unknown;
  response?: unknown;
  error?: string;
  durationMs?: number;
}

export interface RunnerCallbacks {
  onStepStart: (stepId: string) => void;
  onStepComplete: (result: StepResult) => void;
  onComplete: () => void;
}

async function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function executeStep(
  step: StepDef,
  ctx: RunContext
): Promise<{ ok: boolean; status: number; body: unknown; error?: string; durationMs: number }> {
  const base = apiBase();
  const token = getAccessToken();
  const headers: Record<string, string> = {
    "content-type": "application/json",
  };
  if (token) headers["Authorization"] = `Bearer ${token}`;

  const endpointRaw = typeof step.endpoint === "function" ? step.endpoint(ctx) : step.endpoint;
  const url = `${base}${endpointRaw}`;

  const bodyRaw =
    step.method === "GET"
      ? undefined
      : typeof step.body === "function"
      ? step.body(ctx)
      : step.body;

  const t0 = performance.now();
  try {
    const res = await fetch(url, {
      method: step.method,
      headers,
      body: bodyRaw !== undefined ? JSON.stringify(bodyRaw) : undefined,
    });
    const durationMs = Math.round(performance.now() - t0);
    // If the token was rejected, clear it so the next page load gets a fresh one
    if (res.status === 401) {
      const { clearAccessToken } = await import("../../lib/api");
      clearAccessToken();
    }

    let body: unknown;
    const ct = res.headers.get("content-type") ?? "";
    if (ct.includes("application/json") || ct.includes("ndjson")) {
      try {
        body = await res.json();
      } catch {
        body = await res.text();
      }
    } else {
      body = await res.text();
    }

    return { ok: res.ok, status: res.status, body, durationMs };
  } catch (e: unknown) {
    const durationMs = Math.round(performance.now() - t0);
    const msg = e instanceof Error ? e.message : String(e);
    return { ok: false, status: 0, body: null, error: msg, durationMs };
  }
}

export async function runScenario(
  scenario: ScenarioDef,
  callbacks: RunnerCallbacks
): Promise<void> {
  const ctx: RunContext = { results: {} };

  for (const step of scenario.steps) {
    // Apply optional pre-step delay (e.g., waiting for credential expiry)
    if (step.delayMs && step.delayMs > 0) {
      await sleep(step.delayMs);
    }

    callbacks.onStepStart(step.id);

    const bodyForRequest =
      step.method === "GET"
        ? undefined
        : typeof step.body === "function"
        ? step.body(ctx)
        : step.body;

    const { ok, status, body, error, durationMs } = await executeStep(step, ctx);

    // Determine success: either HTTP matches expectStatus exactly,
    // OR it's a failureExpected step and the status matches.
    const statusMatch = status === step.expectStatus;
    const isExpectedFailure = step.failureExpected === true && statusMatch;

    let stepStatus: "success" | "failure" | "expected-failure";
    let checkLabel: string | undefined;

    if (error) {
      // Network-level error
      stepStatus = "failure";
    } else if (isExpectedFailure) {
      stepStatus = "expected-failure";
      if (step.check) {
        const chk = step.check(body);
        checkLabel = chk.label;
      }
    } else if (statusMatch && ok) {
      // HTTP success and matches expected status
      const chk = step.check ? step.check(body) : { pass: true, label: "" };
      stepStatus = chk.pass ? "success" : "failure";
      checkLabel = chk.label;
    } else if (statusMatch && !ok) {
      // Got expected error status — treat as success for non-failure-expected steps too
      // (e.g., expired credential returns 400 which we label as expected)
      stepStatus = step.failureExpected ? "expected-failure" : "failure";
      checkLabel = `HTTP ${status}`;
    } else {
      // Unexpected status
      stepStatus = "failure";
      checkLabel = `Unexpected HTTP ${status} (expected ${step.expectStatus})`;
    }

    // Store result in context for subsequent steps
    if (body !== null && body !== undefined && typeof body === "object") {
      ctx.results[step.id] = body;
    }

    const result: StepResult = {
      stepId: step.id,
      status: stepStatus,
      request: bodyForRequest,
      response: body,
      error: error ?? (stepStatus === "failure" ? checkLabel : undefined),
      durationMs,
    };

    callbacks.onStepComplete(result);

    // Short delay between steps for visual feedback
    await sleep(300);

    // Stop on unexpected failure
    if (stepStatus === "failure" && !step.failureExpected) {
      break;
    }
  }

  callbacks.onComplete();
}
