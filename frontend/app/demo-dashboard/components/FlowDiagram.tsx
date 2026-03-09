"use client";

export interface FlowNode {
  name: string;
  role: string;
  did?: string;
}

export interface FlowEdge {
  label: string;
  highlight?: boolean;
}

interface FlowDiagramProps {
  nodes: FlowNode[];
  edges: FlowEdge[];
  activeNodeIndex?: number;
  stepStatuses?: ("pending" | "success" | "failure" | "expected-failure")[];
}

const ROLE_STYLES: Record<string, { icon: string; accent: string; bg: string }> = {
  Delegator: { icon: "\uD83D\uDC64", accent: "border-blue-300", bg: "bg-blue-50" },
  User: { icon: "\uD83D\uDC64", accent: "border-blue-300", bg: "bg-blue-50" },
  Issuer: { icon: "\uD83C\uDFDB\uFE0F", accent: "border-indigo-300", bg: "bg-indigo-50" },
  Agent: { icon: "\uD83E\uDD16", accent: "border-violet-300", bg: "bg-violet-50" },
  "Sub-Agent": { icon: "\uD83E\uDD16", accent: "border-violet-300", bg: "bg-violet-50" },
  Merchant: { icon: "\uD83C\uDFEA", accent: "border-emerald-300", bg: "bg-emerald-50" },
  Verifier: { icon: "\uD83D\uDD0D", accent: "border-amber-300", bg: "bg-amber-50" },
};

const DEFAULT_STYLE = { icon: "\u2699\uFE0F", accent: "border-gray-300", bg: "bg-gray-50" };

export function FlowDiagram({ nodes, edges, activeNodeIndex, stepStatuses }: FlowDiagramProps) {
  return (
    <div className="bg-gradient-to-r from-slate-50 via-white to-blue-50 rounded-xl border border-slate-200 px-6 py-5 overflow-x-auto">
      <p className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-4">Participants</p>
      <div className="flex items-center justify-center gap-0 min-w-max mx-auto">
        {nodes.map((node, i) => {
          const style = ROLE_STYLES[node.role] ?? DEFAULT_STYLE;
          const isActive = activeNodeIndex === i;
          return (
            <div key={i} className="flex items-center gap-0">
              <div className="flex flex-col items-center">
                <div className={`w-32 text-center ${style.bg} border-2 ${style.accent} rounded-2xl px-3 py-4 shadow-sm transition-all duration-300 ${
                  isActive ? "animate-pulse ring-2 ring-blue-400 ring-offset-1" : ""
                }`}>
                  <div className={`w-10 h-10 rounded-full ${style.bg} border ${style.accent} flex items-center justify-center mx-auto mb-2.5`}>
                    <span className="text-xl">{style.icon}</span>
                  </div>
                  <p className="text-sm font-bold text-gray-800 leading-tight">{node.name}</p>
                  <p className="text-xs text-gray-500 mt-0.5 font-medium">{node.role}</p>
                  {node.did && (
                    <p className="text-xs text-gray-400 font-mono mt-1.5 truncate w-full" title={node.did}>
                      {node.did.slice(0, 18)}...
                    </p>
                  )}
                </div>
              </div>

              {i < edges.length && (() => {
                const edgeStatus = stepStatuses?.[i];
                const edgeDone = edgeStatus === "success" || edgeStatus === "expected-failure";
                const edgeFailed = edgeStatus === "failure";
                const edgeHighlight = edgeDone ? true : edgeFailed ? false : (edges[i].highlight ?? false);
                const lineColor = edgeDone ? "bg-emerald-400" : edgeFailed ? "bg-red-400" : edges[i].highlight ? "bg-emerald-400" : "bg-red-300";
                const arrowColor = edgeDone ? "text-emerald-400" : edgeFailed ? "text-red-400" : edges[i].highlight ? "text-emerald-400" : "text-red-300";
                return (
                  <div className="flex flex-col items-center mx-2">
                    <span className={`text-xs text-center px-3 py-1.5 rounded-full mb-1.5 max-w-32 leading-tight font-medium ${
                      edgeHighlight
                        ? "bg-emerald-100 text-emerald-700 border border-emerald-200"
                        : "bg-red-50 text-red-600 border border-red-200"
                    }`}>
                      {edges[i].label}
                    </span>
                    <div className="flex items-center">
                      <div className={`w-10 h-0.5 ${lineColor} transition-colors duration-300`} />
                      <span className={`${arrowColor} transition-colors duration-300`}>{"\u25B6"}</span>
                    </div>
                  </div>
                );
              })()}
            </div>
          );
        })}
      </div>
    </div>
  );
}
