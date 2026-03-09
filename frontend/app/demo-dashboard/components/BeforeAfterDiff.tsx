"use client";

import { SummarySnapshot } from "./SystemPulse";

interface BeforeAfterDiffProps {
  before: SummarySnapshot | null;
  after: SummarySnapshot | null;
}

interface DiffRow {
  label: string;
  before: string | number;
  after: string | number;
  delta: number;
  isPositive: (delta: number) => boolean;
}

function formatUsd(n: number): string {
  return `$${n.toFixed(2)}`;
}

export function BeforeAfterDiff({ before, after }: BeforeAfterDiffProps) {
  if (!before || !after) return null;

  const rows: DiffRow[] = [
    {
      label: "Agents",
      before: before.agents_count,
      after: after.agents_count,
      delta: after.agents_count - before.agents_count,
      isPositive: (d) => d >= 0,
    },
    {
      label: "Active Credentials",
      before: before.credentials_active,
      after: after.credentials_active,
      delta: after.credentials_active - before.credentials_active,
      isPositive: (d) => d >= 0,
    },
    {
      label: "Revoked Credentials",
      before: before.credentials_revoked,
      after: after.credentials_revoked,
      delta: after.credentials_revoked - before.credentials_revoked,
      isPositive: (d) => d >= 0,
    },
    {
      label: "Audit Events",
      before: before.audit_events_count,
      after: after.audit_events_count,
      delta: after.audit_events_count - before.audit_events_count,
      isPositive: (d) => d >= 0,
    },
    {
      label: "Mandate Spends",
      before: before.mandate_spends_count,
      after: after.mandate_spends_count,
      delta: after.mandate_spends_count - before.mandate_spends_count,
      isPositive: (d) => d >= 0,
    },
    {
      label: "Total Spend (USD)",
      before: formatUsd(before.total_spend_usd),
      after: formatUsd(after.total_spend_usd),
      delta: after.total_spend_usd - before.total_spend_usd,
      isPositive: (d) => d >= 0,
    },
  ];

  // Only render if something changed
  const changed = rows.some((r) => r.delta !== 0);
  if (!changed) return null;

  return (
    <div className="mt-5">
      <p className="text-xs font-semibold text-gray-400 uppercase tracking-wide mb-3">
        System State Changes (Before → After)
      </p>
      <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
        {/* Chain validity row */}
        <div className="px-4 py-3 bg-gray-50 border-b border-gray-100 flex items-center justify-between">
          <span className="text-xs font-medium text-gray-600">Audit Chain</span>
          <div className="flex items-center gap-3">
            <span className={`text-xs font-medium px-2 py-0.5 rounded-full ${
              before.chain_valid
                ? "bg-emerald-100 text-emerald-700"
                : "bg-red-100 text-red-600"
            }`}>
              {before.chain_valid ? "✓ valid" : "⚠ broken"}
            </span>
            <span className="text-gray-300 text-xs">→</span>
            <span className={`text-xs font-medium px-2 py-0.5 rounded-full ${
              after.chain_valid
                ? "bg-emerald-100 text-emerald-700"
                : "bg-red-100 text-red-600"
            }`}>
              {after.chain_valid ? "✓ valid" : "⚠ broken"}
            </span>
          </div>
        </div>

        {/* Metric rows */}
        {rows.map((row) => (
          <div
            key={row.label}
            className="px-4 py-3 border-b border-gray-50 last:border-b-0 flex items-center justify-between"
          >
            <span className="text-xs text-gray-600">{row.label}</span>
            <div className="flex items-center gap-3">
              <span className="text-xs font-mono text-gray-500">{row.before}</span>
              <span className="text-gray-300 text-xs">→</span>
              <span className="text-xs font-mono text-gray-800 font-medium">{row.after}</span>
              {row.delta !== 0 && (
                <span className={`text-xs font-mono font-semibold ${
                  row.isPositive(row.delta) ? "text-emerald-600" : "text-red-500"
                }`}>
                  {row.delta > 0 ? "+" : ""}
                  {typeof row.delta === "number" && Math.abs(row.delta) < 1
                    ? row.delta.toFixed(2)
                    : row.delta}
                </span>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
