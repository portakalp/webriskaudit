import type { NodeStatus } from "./types"

// One node per check the API runs: email and transport checks on the inner
// ring, header and informational checks on the outer ring.
const GRAPH_NODES = {
  inner: [
    { id: "spf", label: "SPF" },
    { id: "dmarc", label: "DMARC" },
    { id: "dkim", label: "DKIM" },
    { id: "tls", label: "TLS" },
    { id: "redirect", label: "Redirect" },
    { id: "hsts", label: "HSTS" },
  ],
  outer: [
    { id: "csp", label: "CSP" },
    { id: "frames", label: "Frames" },
    { id: "nosniff", label: "Nosniff" },
    { id: "referrer", label: "Referrer" },
    { id: "cookies", label: "Cookies" },
    { id: "server", label: "Server" },
    { id: "cdn", label: "CDN" },
    { id: "privacy", label: "Privacy" },
    { id: "permissions", label: "Permissions" },
    { id: "deprecated", label: "Legacy" },
  ],
}

const SIZE = 440
const CENTER = SIZE / 2
const INNER_RADIUS = 92
const OUTER_RADIUS = 168
const NODE_RADIUS = 14

const NODE_FILL: Record<NodeStatus, string> = {
  idle: "#e2e8f0", // slate-200
  scanning: "#ea580c", // orange-600
  complete: "#059669", // emerald-600
}

const LABEL_CLASS: Record<NodeStatus, string> = {
  idle: "fill-slate-600",
  scanning: "fill-orange-800",
  complete: "fill-emerald-800",
}

interface PlacedNode {
  id: string
  label: string
  x: number
  y: number
}

function placeRing(nodes: { id: string; label: string }[], radius: number, offset: number): PlacedNode[] {
  return nodes.map((node, index) => {
    const angle = -Math.PI / 2 + offset + (2 * Math.PI * index) / nodes.length
    return { ...node, x: CENTER + radius * Math.cos(angle), y: CENTER + radius * Math.sin(angle) }
  })
}

// The outer ring is turned by half a step so its nodes sit between the inner ones.
const PLACED: PlacedNode[] = [
  ...placeRing(GRAPH_NODES.inner, INNER_RADIUS, 0),
  ...placeRing(GRAPH_NODES.outer, OUTER_RADIUS, Math.PI / GRAPH_NODES.outer.length),
]

interface NetworkGraphProps {
  completed: ReadonlySet<string>
  active: ReadonlySet<string>
}

/** Decorative graph of the checks; the scan's status is announced elsewhere. */
export function NetworkGraph({ completed, active }: NetworkGraphProps) {
  const statusOf = (id: string): NodeStatus => {
    if (completed.has(id)) return "complete"
    if (active.has(id)) return "scanning"
    return "idle"
  }

  return (
    <div className="mx-auto w-full max-w-md rounded-xl border-2 border-slate-200 bg-white p-3">
      <svg viewBox={`0 0 ${SIZE} ${SIZE}`} className="h-auto w-full" aria-hidden="true" focusable="false">
        {PLACED.map((node) => {
          const status = statusOf(node.id)
          return (
            <line
              key={`line-${node.id}`}
              x1={CENTER}
              y1={CENTER}
              x2={node.x}
              y2={node.y}
              stroke={status === "idle" ? "#cbd5e1" : NODE_FILL[status]}
              strokeWidth={status === "scanning" ? 2 : 1}
              strokeDasharray={status === "scanning" ? "5 5" : undefined}
              opacity={status === "idle" ? 0.5 : 0.8}
            />
          )
        })}

        <circle cx={CENTER} cy={CENTER} r={32} fill="#f8fafc" stroke="#c2410c" strokeWidth={3} />
        <text x={CENTER} y={CENTER} textAnchor="middle" dy="0.35em" className="fill-slate-900 text-[11px] font-bold">
          Domain
        </text>

        {PLACED.map((node) => {
          const status = statusOf(node.id)
          return (
            <g key={node.id}>
              <circle
                cx={node.x}
                cy={node.y}
                r={NODE_RADIUS}
                fill={NODE_FILL[status]}
                stroke={status === "idle" ? "#94a3b8" : NODE_FILL[status]}
                strokeWidth={2}
                className={`transition-colors duration-300 ${status === "scanning" ? "motion-safe:animate-pulse" : ""}`}
              />
              {status === "complete" && (
                <path
                  d={`M ${node.x - 5} ${node.y} l 3.5 3.5 l 6.5 -7`}
                  fill="none"
                  stroke="#ffffff"
                  strokeWidth={2.5}
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
              )}
              <text
                x={node.x}
                y={node.y + NODE_RADIUS + 14}
                textAnchor="middle"
                className={`text-[11px] font-semibold ${LABEL_CLASS[status]}`}
              >
                {node.label}
              </text>
            </g>
          )
        })}
      </svg>
    </div>
  )
}
