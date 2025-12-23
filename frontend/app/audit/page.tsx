"use client";

import { useEffect, useState } from "react";
import { apiGet } from "../../lib/api";

type AuditEvent = {
  id: string;
  event_type: string;
  actor: string;
  resource_type: string;
  resource_id: string;
  payload: any;
  created_at: string;
};

export default function AuditPage() {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [error, setError] = useState<string>("");

  useEffect(() => {
    (async () => {
      try {
        const data = await apiGet<{ events: AuditEvent[] }>("/v1/audit?limit=50");
        setEvents(data.events || []);
      } catch (e: any) {
        setError(String(e?.message || e));
      }
    })();
  }, []);

  return (
    <main style={{ maxWidth: 1000 }}>
      <h1>Audit</h1>
      {error && (
        <div style={{ marginTop: 16, padding: 12, border: "1px solid #f2b8b5", borderRadius: 8, background: "#fff5f5" }}>
          <p style={{ color: "crimson", margin: 0 }}>{error}</p>
          {(String(error).startsWith("401") || String(error).startsWith("403")) && (
            <p style={{ marginTop: 8, marginBottom: 0 }}>
              Please <a href="/login">login</a> (tenant admin required).
            </p>
          )}
        </div>
      )}
      <p>Latest events (up to 50)</p>
      <table style={{ width: "100%", borderCollapse: "collapse" }}>
        <thead>
          <tr>
            <th style={{ textAlign: "left", borderBottom: "1px solid #ddd" }}>time</th>
            <th style={{ textAlign: "left", borderBottom: "1px solid #ddd" }}>event</th>
            <th style={{ textAlign: "left", borderBottom: "1px solid #ddd" }}>actor</th>
            <th style={{ textAlign: "left", borderBottom: "1px solid #ddd" }}>resource</th>
          </tr>
        </thead>
        <tbody>
          {events.map((e) => (
            <tr key={e.id}>
              <td style={{ padding: "6px 4px", verticalAlign: "top" }}>{e.created_at}</td>
              <td style={{ padding: "6px 4px", verticalAlign: "top" }}>
                <code>{e.event_type}</code>
              </td>
              <td style={{ padding: "6px 4px", verticalAlign: "top" }}>{e.actor}</td>
              <td style={{ padding: "6px 4px", verticalAlign: "top" }}>
                <code>
                  {e.resource_type}:{e.resource_id}
                </code>
              </td>
            </tr>
          ))}
          {events.length === 0 && (
            <tr>
              <td colSpan={4} style={{ padding: "8px 4px" }}>
                No events yet.
              </td>
            </tr>
          )}
        </tbody>
      </table>
      <p style={{ marginTop: 16 }}>
        <a href="/">Back</a>
      </p>
    </main>
  );
}
