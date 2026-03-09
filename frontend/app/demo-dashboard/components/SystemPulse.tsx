"use client";

import { useEffect, useState, useCallback } from "react";
import { apiGet, apiPost } from "../../../lib/api";

export interface SummarySnapshot {
  agents_count: number;
  credentials_active: number;
  credentials_revoked: number;
  delegations_count: number;
  audit_events_count: number;
  chain_valid: boolean;
  trust_events_count: number;
  mandate_spends_count: number;
  total_spend_usd: number;
}

function StatPill({
  label,
  value,
  sub,
  accent,
}: {
  label: string;
  value: string | number;
  sub?: string;
  accent?: "green" | "red" | "blue" | "gray";
}) {
  const accentClass: Record<string, string> = {
    green: "text-emerald-600",
    red: "text-red-500",
    blue: "text-blue-600",
    gray: "text-gray-500",
  };
  const color = accentClass[accent ?? "blue"];

  return (
    <div className="flex flex-col items-center px-5 py-3 border-r border-gray-100 last:border-r-0">
      <span className={`text-2xl font-bold tabular-nums ${color}`}>{value}</span>
      <span className="text-xs text-gray-500 mt-0.5 text-center leading-tight">{label}</span>
      {sub && <span className="text-xs font-medium mt-0.5 text-center leading-tight text-gray-400">{sub}</span>}
    </div>
  );
}

export function SystemPulse() {
  const [data, setData] = useState<SummarySnapshot | null>(null);
  const [loading, setLoading] = useState(true);
  const [seeding, setSeeding] = useState(false);
  const [seedError, setSeedError] = useState<string | null>(null);

  const fetchSummary = useCallback(async () => {
    try {
      const snap = await apiGet<SummarySnapshot>("/v1/demo/summary");
      setData(snap);
    } catch {
      // Silently ignore — endpoint may not be available in older backends
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchSummary();
  }, [fetchSummary]);

  const handleSeed = async () => {
    setSeeding(true);
    setSeedError(null);
    try {
      await apiPost("/v1/demo/seed", { profile: "standard" });
      await fetchSummary();
    } catch (e: unknown) {
      setSeedError(e instanceof Error ? e.message : "Seed failed");
    } finally {
      setSeeding(false);
    }
  };

  if (loading) {
    return (
      <div className="bg-white rounded-xl border border-gray-200 shadow-sm px-6 py-5 mb-6">
        <div className="flex items-center gap-2 text-gray-400 text-sm">
          <span className="inline-block w-3 h-3 rounded-full bg-gray-200 animate-pulse" />
          Loading system state…
        </div>
      </div>
    );
  }

  if (!data) return null;

  const isEmpty = data.agents_count === 0;

  return (
    <div className="bg-white rounded-xl border border-gray-200 shadow-sm px-6 py-5 mb-6">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h3 className="text-sm font-semibold text-gray-700">System State</h3>
          <p className="text-xs text-gray-400 mt-0.5">Live snapshot of your demo tenant's data</p>
        </div>
        <div className="flex items-center gap-3">
          {!isEmpty && (
            <button
              onClick={fetchSummary}
              className="text-xs text-gray-500 hover:text-gray-700 border border-gray-200 rounded-lg px-3 py-1.5 transition-colors"
            >
              Refresh
            </button>
          )}
          <button
            onClick={handleSeed}
            disabled={seeding || !isEmpty}
            className={`text-xs font-semibold rounded-lg px-4 py-1.5 transition-all ${
              isEmpty
                ? "bg-blue-600 text-white hover:bg-blue-700 shadow-sm"
                : "bg-gray-100 text-gray-400 cursor-not-allowed"
            }`}
          >
            {seeding ? "Seeding…" : isEmpty ? "Load Demo Data" : "Data Loaded"}
          </button>
        </div>
      </div>

      {seedError && (
        <div className="mb-4 px-3 py-2 bg-red-50 border border-red-200 rounded-lg text-xs text-red-600">
          {seedError}
        </div>
      )}

      {isEmpty ? (
        <div className="flex flex-col items-center py-6 text-center">
          <div className="w-10 h-10 rounded-full bg-blue-50 border border-blue-100 flex items-center justify-center mb-3">
            <span className="text-xl">🌱</span>
          </div>
          <p className="text-sm font-medium text-gray-700">No demo data yet</p>
          <p className="text-xs text-gray-400 mt-1 max-w-xs">
            Click "Load Demo Data" to populate 30 agents, 50+ credentials, delegation chains, and a
            verified audit trail.
          </p>
        </div>
      ) : (
        <div className="flex flex-wrap divide-x divide-gray-100 -mx-1">
          <StatPill
            label="Agents"
            value={data.agents_count}
            sub="registered"
            accent="blue"
          />
          <StatPill
            label="Credentials"
            value={data.credentials_active}
            sub={`${data.credentials_revoked} revoked`}
            accent="green"
          />
          <StatPill
            label="Delegations"
            value={data.delegations_count}
            sub="in registry"
            accent="blue"
          />
          <StatPill
            label="Audit Events"
            value={data.audit_events_count}
            sub={data.chain_valid ? "✓ chain valid" : "⚠ chain broken"}
            accent={data.chain_valid ? "green" : "red"}
          />
          <StatPill
            label="Trust Signals"
            value={data.trust_events_count}
            sub="behavioral events"
            accent="blue"
          />
          <StatPill
            label="Total Spend"
            value={`$${data.total_spend_usd.toFixed(2)}`}
            sub={`${data.mandate_spends_count} transactions`}
            accent="gray"
          />
        </div>
      )}
    </div>
  );
}
