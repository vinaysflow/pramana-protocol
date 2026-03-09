"use client";

import { useState } from "react";

interface CodePanelProps {
  label: string;
  data: unknown;
  defaultOpen?: boolean;
}

function decodeJwt(jwt: string): string {
  try {
    const parts = jwt.split(".");
    if (parts.length !== 3) return jwt;
    const pad = (s: string) => s + "=".repeat((4 - (s.length % 4)) % 4);
    const header = JSON.parse(atob(pad(parts[0])));
    const payload = JSON.parse(atob(pad(parts[1].replace(/-/g, "+").replace(/_/g, "/"))));
    return JSON.stringify(
      { header, payload, signature: parts[2].slice(0, 16) + "…[truncated]" },
      null,
      2
    );
  } catch {
    return jwt;
  }
}

function formatValue(data: unknown): string {
  if (typeof data === "string") {
    if (data.split(".").length === 3 && data.length > 100) {
      return decodeJwt(data);
    }
    return data;
  }
  return JSON.stringify(data, null, 2);
}

export function CodePanel({ label, data, defaultOpen = false }: CodePanelProps) {
  const [open, setOpen] = useState(defaultOpen);
  const [copied, setCopied] = useState(false);
  const text = formatValue(data);

  async function copy() {
    await navigator.clipboard.writeText(
      typeof data === "string" ? data : JSON.stringify(data, null, 2)
    );
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }

  return (
    <div className="border border-gray-200 rounded-md overflow-hidden text-sm">
      <button
        onClick={() => setOpen((o) => !o)}
        className="w-full flex items-center justify-between px-3 py-2 bg-gray-50 hover:bg-gray-100 text-left font-mono text-xs text-gray-600"
      >
        <span>{label}</span>
        <span className="text-gray-400">{open ? "▲" : "▼"}</span>
      </button>
      {open && (
        <div className="relative">
          <button
            onClick={copy}
            className="absolute top-2 right-2 text-xs px-2 py-0.5 rounded bg-gray-200 hover:bg-gray-300 text-gray-600 z-10"
          >
            {copied ? "Copied!" : "Copy"}
          </button>
          <pre className="p-3 bg-gray-950 text-gray-100 text-xs overflow-x-auto max-h-64 whitespace-pre-wrap">
            {text}
          </pre>
        </div>
      )}
    </div>
  );
}
