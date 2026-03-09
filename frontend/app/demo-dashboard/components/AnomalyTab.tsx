"use client";

import { useState, useEffect } from "react";
import { apiGet } from "../../../lib/api";

interface AnomalyEvent {
  event_type: string;
  score_delta: number;
  created_at: string;
}

interface AnomalyAgent {
  name: string;
  did: string;
  spiffe_id: string | null;
  trust_score: number;
  risk_tier: string;
  recent_delta: number;
  failure_rate: number;
  anomaly_reasons: string[];
  recent_events: AnomalyEvent[];
}

interface AnomalyMonitor {
  flagged_count: number;
  total_agents_checked: number;
  anomalies: AnomalyAgent[];
  generated_at: string;
}

const TIER_COLORS: Record<string, string> = {
  insurable: "text-emerald-600 bg-emerald-50",
  elevated: "text-amber-600 bg-amber-50",
  review: "text-orange-600 bg-orange-50",
  uninsurable: "text-red-600 bg-red-50",
};

export function AnomalyTab() {
  const [data, setData] = useState<AnomalyMonitor | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);

  useEffect(() => {
    apiGet<AnomalyMonitor>("/v1/trust/anomalies")
      .then(setData)
      .catch((e) => setError(e instanceof Error ? e.message : String(e)))
      .finally(() => setLoading(false));
  }, []);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-gradient-to-r from-red-600 to-rose-600 rounded-2xl p-6 text-white">
        <div className="flex items-start gap-4">
          <div className="w-12 h-12 bg-white/20 rounded-xl flex items-center justify-center text-2xl flex-shrink-0">⚠️</div>
          <div>
            <h2 className="text-lg font-bold">Anomaly Detection</h2>
            <p className="text-red-100 text-sm mt-1">
              Agents with anomalous trust behavior: rapid score drops, high failure rates,
              scope violation attempts, or critical risk scores.
            </p>
          </div>
        </div>
      </div>

      {loading && (
        <div className="py-12 text-center text-gray-400">
          <div className="w-6 h-6 border-2 border-red-400 border-t-transparent rounded-full animate-spin mx-auto mb-3" />
          <p className="text-sm">Scanning for anomalies...</p>
        </div>
      )}

      {error && (
        <div className="bg-red-50 border border-red-200 rounded-xl p-4 text-sm text-red-700">
          <p className="font-semibold">Failed to load anomaly data</p>
          <p className="font-mono text-xs mt-1">{error}</p>
        </div>
      )}

      {data && !loading && data.total_agents_checked === 0 && (
        <div className="bg-blue-50 border border-blue-200 rounded-2xl p-6 text-center">
          <p className="text-2xl mb-2">🌱</p>
          <p className="text-sm font-semibold text-blue-800">No agents to monitor yet</p>
          <p className="text-xs text-blue-600 mt-1">
            Click <strong>"Load Demo Data"</strong> in the System State bar above to seed agents with trust event histories.
          </p>
        </div>
      )}

      {data && !loading && data.total_agents_checked > 0 && (
        <>
          {/* Summary */}
          <div className="grid grid-cols-3 gap-4">
            <div className={`rounded-2xl p-5 text-center ${data.flagged_count > 0 ? "bg-red-50" : "bg-emerald-50"}`}>
              <p className={`text-4xl font-black ${data.flagged_count > 0 ? "text-red-600" : "text-emerald-600"}`}>
                {data.flagged_count}
              </p>
              <p className="text-sm text-gray-600 mt-1">Flagged agents</p>
            </div>
            <div className="bg-white border border-gray-200 rounded-2xl p-5 text-center">
              <p className="text-4xl font-black text-gray-800">{data.total_agents_checked}</p>
              <p className="text-sm text-gray-600 mt-1">Agents checked</p>
            </div>
            <div className="bg-white border border-gray-200 rounded-2xl p-5 text-center">
              <p className="text-4xl font-black text-indigo-600">
                {data.total_agents_checked > 0
                  ? Math.round((1 - data.flagged_count / data.total_agents_checked) * 100)
                  : 100}%
              </p>
              <p className="text-sm text-gray-600 mt-1">Fleet healthy</p>
            </div>
          </div>

          {data.flagged_count === 0 ? (
            <div className="bg-emerald-50 border border-emerald-200 rounded-2xl p-8 text-center">
              <p className="text-2xl mb-2">✅</p>
              <p className="text-emerald-700 font-semibold">No anomalies detected</p>
              <p className="text-emerald-600 text-sm mt-1">All agents are behaving within expected trust parameters.</p>
            </div>
          ) : (
            <div className="space-y-3">
              {data.anomalies.map((agent) => {
                const isExpanded = expanded === agent.did;
                const tierColor = TIER_COLORS[agent.risk_tier] || TIER_COLORS.elevated;
                return (
                  <div key={agent.did} className="bg-white border border-gray-200 rounded-2xl overflow-hidden">
                    <button
                      onClick={() => setExpanded(isExpanded ? null : agent.did)}
                      className="w-full p-4 text-left"
                    >
                      <div className="flex items-start gap-4">
                        <div className="w-10 h-10 bg-red-100 rounded-xl flex items-center justify-center text-red-600 font-bold text-sm flex-shrink-0">
                          {agent.trust_score}
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className="text-sm font-bold text-gray-800">{agent.name}</span>
                            <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${tierColor}`}>
                              {agent.risk_tier}
                            </span>
                            {agent.spiffe_id && (
                              <span className="text-xs bg-indigo-50 text-indigo-600 px-2 py-0.5 rounded-full">SPIFFE</span>
                            )}
                            <span className="ml-auto text-xs text-gray-400">{isExpanded ? "▲" : "▼"}</span>
                          </div>
                          <p className="text-xs font-mono text-gray-400 mt-0.5 truncate">{agent.did}</p>
                          <div className="flex gap-3 mt-2">
                            {agent.anomaly_reasons.map((reason, i) => (
                              <div key={i} className="flex items-center gap-1 text-xs text-red-600">
                                <span className="w-1.5 h-1.5 rounded-full bg-red-500 flex-shrink-0" />
                                {reason}
                              </div>
                            ))}
                          </div>
                        </div>
                        <div className="text-right flex-shrink-0">
                          <p className={`text-xs font-semibold ${agent.recent_delta >= 0 ? "text-emerald-600" : "text-red-600"}`}>
                            {agent.recent_delta >= 0 ? "+" : ""}{agent.recent_delta}
                          </p>
                          <p className="text-xs text-gray-400">{(agent.failure_rate * 100).toFixed(0)}% fail</p>
                        </div>
                      </div>
                    </button>
                    {isExpanded && (
                      <div className="px-4 pb-4 pt-0 border-t border-gray-100 mt-0">
                        <div className="space-y-2 mt-3">
                          <p className="text-xs font-semibold text-gray-600">Recent trust events:</p>
                          {agent.recent_events.map((ev, i) => (
                            <div key={i} className="flex items-center gap-3 text-xs">
                              <span className="font-mono text-gray-400 flex-shrink-0">{ev.created_at.slice(0, 16)}</span>
                              <span className={`px-2 py-0.5 rounded text-xs ${
                                ev.event_type.includes("failure") || ev.event_type.includes("violation")
                                  ? "bg-red-50 text-red-600"
                                  : "bg-emerald-50 text-emerald-600"
                              }`}>{ev.event_type}</span>
                              <span className={`font-bold ${ev.score_delta >= 0 ? "text-emerald-600" : "text-red-600"}`}>
                                {ev.score_delta >= 0 ? "+" : ""}{ev.score_delta}
                              </span>
                            </div>
                          ))}
                        </div>
                        <div className="mt-4 p-3 bg-amber-50 border border-amber-100 rounded-xl text-xs text-amber-700">
                          <strong>Recommended action:</strong> Review this agent&apos;s delegations and credentials.
                          Consider revoking credentials and requiring re-attestation via
                          <span className="font-mono bg-amber-100 px-1 rounded ml-1">POST /v1/identity/attest</span>.
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}

          <p className="text-xs text-gray-400 text-center">Last scan: {data.generated_at}</p>
        </>
      )}
    </div>
  );
}
