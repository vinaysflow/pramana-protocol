"use client";

import { useState } from "react";
import { StepDef } from "../scenarios";
import { CodePanel } from "./CodePanel";
import { StatusBadge, BadgeStatus } from "./StatusBadge";

export interface StepState {
  id: string;
  status: BadgeStatus;
  request?: unknown;
  response?: unknown;
  error?: string;
  durationMs?: number;
}

interface StepCardProps {
  step: StepDef;
  state: StepState;
  index: number;
}

export function StepCard({ step, state, index }: StepCardProps) {
  const [showTechnical, setShowTechnical] = useState(false);

  const bgByStatus: Record<BadgeStatus, string> = {
    pending: "border-gray-200 bg-white",
    running: "border-blue-300 bg-blue-50/30 ring-1 ring-blue-200",
    success: "border-emerald-200 bg-emerald-50/20",
    failure: "border-red-200 bg-red-50/20",
    "expected-failure": "border-emerald-200 bg-emerald-50/20",
  };

  const stepNumColor: Record<BadgeStatus, string> = {
    pending: "bg-gray-100 text-gray-500",
    running: "bg-blue-500 text-white animate-pulse",
    success: "bg-emerald-500 text-white",
    failure: "bg-red-500 text-white",
    "expected-failure": "bg-emerald-500 text-white",
  };

  const methodColor =
    step.method === "GET"
      ? "bg-sky-100 text-sky-700 border-sky-200"
      : "bg-violet-100 text-violet-700 border-violet-200";

  return (
    <div className={`border rounded-xl p-5 shadow-sm transition-all duration-300 ${bgByStatus[state.status]}`}>
      {/* Header row */}
      <div className="flex items-start justify-between gap-4">
        <div className="flex items-start gap-3.5 flex-1 min-w-0">
          <span className={`flex-shrink-0 w-8 h-8 rounded-full text-xs font-bold flex items-center justify-center transition-colors ${stepNumColor[state.status]}`}>
            {index + 1}
          </span>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2.5 flex-wrap">
              <p className="font-semibold text-gray-900">{step.title}</p>
              {step.controlLabel && (
                <span className="inline-flex items-center px-2 py-0.5 rounded-md bg-gray-100 text-gray-500 text-xs border border-gray-200">
                  {step.controlLabel}
                </span>
              )}
            </div>

            {/* Plain English explanation — always visible */}
            <p className="text-gray-600 text-sm mt-1.5 leading-relaxed">
              {step.plainEnglish}
            </p>

            {/* API endpoint pill */}
            <div className="flex items-center gap-2 mt-3">
              <span className={`inline-block px-2 py-0.5 rounded-md text-xs font-mono font-bold border ${methodColor}`}>
                {step.method}
              </span>
              <code className="text-xs text-gray-500 font-mono">
                {typeof step.endpoint === "string" ? step.endpoint : "(dynamic)"}
              </code>
              {step.failureExpected && (
                <span className="inline-flex items-center px-2 py-0.5 rounded-md bg-amber-50 text-amber-700 text-xs border border-amber-200 font-medium">
                  Expected: rejected by protocol
                </span>
              )}
            </div>

            {/* Technical detail toggle */}
            <button
              onClick={() => setShowTechnical((t) => !t)}
              className="mt-2.5 text-xs text-blue-600 hover:text-blue-800 font-medium flex items-center gap-1"
            >
              <span className="text-blue-400">{showTechnical ? "▾" : "▸"}</span>
              {showTechnical ? "Hide technical details" : "Show technical details"}
            </button>
            {showTechnical && (
              <div className="mt-2 px-3 py-2.5 bg-slate-50 border border-slate-200 rounded-lg text-xs text-slate-600 leading-relaxed">
                {step.technicalDetail}
              </div>
            )}
          </div>
        </div>
        <div className="flex-shrink-0 pt-0.5 flex items-center gap-2">
          {state.durationMs !== undefined && state.status !== "pending" && state.status !== "running" && (
            <span className="text-xs text-gray-400 font-mono">{state.durationMs}ms</span>
          )}
          <StatusBadge status={state.status} />
        </div>
      </div>

      {/* Error display */}
      {state.error && (
        <div className="mt-4 px-3.5 py-2.5 bg-red-50 border border-red-200 rounded-lg text-xs text-red-700">
          <p className="font-semibold">Error</p>
          <p className="font-mono mt-0.5 break-all">{state.error}</p>
        </div>
      )}

      {/* Request / Response panels */}
      {(state.request !== undefined || state.response !== undefined) && (
        <div className="mt-4 space-y-2">
          {state.request !== undefined && (
            <CodePanel label="Request body" data={state.request} />
          )}
          {state.response !== undefined && (
            <CodePanel label="Response" data={state.response} defaultOpen />
          )}
        </div>
      )}
    </div>
  );
}
