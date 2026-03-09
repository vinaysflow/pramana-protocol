"use client";

export type BadgeStatus =
  | "pending"
  | "running"
  | "success"
  | "failure"
  | "expected-failure";

const CONFIG: Record<BadgeStatus, { label: string; classes: string }> = {
  pending: {
    label: "Pending",
    classes: "bg-gray-50 text-gray-400 border border-gray-200",
  },
  running: {
    label: "Running...",
    classes: "bg-blue-50 text-blue-600 border border-blue-200 animate-pulse",
  },
  success: {
    label: "\u2713 Passed",
    classes: "bg-emerald-50 text-emerald-700 border border-emerald-200",
  },
  failure: {
    label: "\u2717 Failed",
    classes: "bg-red-50 text-red-700 border border-red-200",
  },
  "expected-failure": {
    label: "\u2713 Correctly Rejected",
    classes: "bg-emerald-50 text-emerald-700 border border-emerald-200",
  },
};

export function StatusBadge({ status }: { status: BadgeStatus }) {
  const { label, classes } = CONFIG[status];
  return (
    <span className={`inline-flex items-center px-3 py-1 rounded-lg text-xs font-semibold ${classes}`}>
      {label}
    </span>
  );
}
