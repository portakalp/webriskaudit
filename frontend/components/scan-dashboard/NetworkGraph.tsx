"use client"

import { CheckCircle, XCircle, Globe, Lock, Mail, ShieldCheck, Shield, FileCheck, AlertTriangle, FileText, Search, Calculator } from "lucide-react"
import type { GraphNode, NodeStatus } from "./types"

interface NetworkGraphProps {
  completedTests: string[]
  activeTests: string[]
}

// Security test definitions with icons
const SECURITY_TESTS = [
  { id: "dns", name: "DNS", Icon: Globe },
  { id: "ssl", name: "SSL", Icon: Lock },
  { id: "spf", name: "SPF", Icon: Mail },
  { id: "dmarc", name: "DMARC", Icon: ShieldCheck },
  { id: "waf", name: "WAF", Icon: Shield },
  { id: "headers", name: "Headers", Icon: FileCheck },
  { id: "blacklist", name: "Blacklist", Icon: AlertTriangle },
  { id: "compliance", name: "Privacy Tech", Icon: FileText },
  { id: "typo", name: "Typo", Icon: Search },
  { id: "score", name: "Score", Icon: Calculator },
]

export function NetworkGraph({ completedTests, activeTests }: NetworkGraphProps) {
  const centerX = 200
  const centerY = 200
  const innerRadius = 80
  const outerRadius = 140

  // Calculate positions for nodes in circular layout
  const getNodePosition = (index: number, total: number, radius: number) => {
    const angle = (index * 2 * Math.PI) / total - Math.PI / 2
    return {
      x: centerX + radius * Math.cos(angle),
      y: centerY + radius * Math.sin(angle),
    }
  }

  // Determine node status
  const getNodeStatus = (testId: string): NodeStatus => {
    if (completedTests.includes(testId)) return "complete"
    if (activeTests.includes(testId)) return "scanning"
    return "idle"
  }

  // Create nodes array with positions
  const nodes: GraphNode[] = SECURITY_TESTS.map((test, index) => {
    const isInnerRing = index < 5
    const ringIndex = isInnerRing ? index : index - 5
    const ringTotal = isInnerRing ? 5 : 4
    const radius = isInnerRing ? innerRadius : outerRadius
    const position = getNodePosition(ringIndex, ringTotal, radius)

    return {
      id: test.id,
      name: test.name,
      status: getNodeStatus(test.id),
      x: position.x,
      y: position.y,
    }
  })

  // Get node color based on status
  const getNodeColor = (status: NodeStatus) => {
    switch (status) {
      case "complete":
        return "#10b981" // emerald-500
      case "scanning":
        return "#f97316" // orange-500
      case "failed":
        return "#ef4444" // red-500
      default:
        return "#94a3b8" // slate-400
    }
  }

  // Get status icon
  const getStatusIcon = (status: NodeStatus) => {
    if (status === "complete") return <CheckCircle className="w-4 h-4" />
    if (status === "failed") return <XCircle className="w-4 h-4" />
    return null
  }

  return (
    <div className="w-full bg-white border-2 border-slate-200 rounded-xl p-6 overflow-hidden">
      <svg
        viewBox="0 0 400 400"
        className="w-full h-auto"
        style={{ maxHeight: "500px" }}
      >
        {/* Grid background pattern */}
        <defs>
          <pattern
            id="grid"
            width="20"
            height="20"
            patternUnits="userSpaceOnUse"
          >
            <path
              d="M 20 0 L 0 0 0 20"
              fill="none"
              stroke="#e2e8f0"
              strokeWidth="0.5"
            />
          </pattern>

          {/* Gradient for scanning nodes */}
          <linearGradient id="nodeGradient" x1="0%" y1="0%" x2="0%" y2="100%">
            <stop offset="0%" stopColor="#f97316" stopOpacity="0.9" />
            <stop offset="100%" stopColor="#ea580c" stopOpacity="1" />
          </linearGradient>

          {/* Enhanced glow filter for scanning nodes */}
          <filter id="glow" x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="4" result="coloredBlur" />
            <feMerge>
              <feMergeNode in="coloredBlur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>

          {/* Shadow filter for completed nodes */}
          <filter id="shadow">
            <feDropShadow dx="0" dy="2" stdDeviation="3" floodOpacity="0.3" />
          </filter>
        </defs>

        {/* Background grid */}
        <rect width="400" height="400" fill="url(#grid)" opacity="0.3" />

        {/* Connection lines from center to each node */}
        {nodes.map((node) => (
          <line
            key={`line-${node.id}`}
            x1={centerX}
            y1={centerY}
            x2={node.x}
            y2={node.y}
            stroke={
              node.status === "scanning"
                ? "#f97316"
                : node.status === "complete"
                ? "#10b981"
                : "#cbd5e1"
            }
            strokeWidth={node.status === "scanning" ? "2" : "1"}
            strokeDasharray={node.status === "scanning" ? "5,5" : "none"}
            className={node.status === "scanning" ? "animate-pulse" : ""}
            opacity={node.status === "idle" ? 0.3 : 0.8}
          />
        ))}

        {/* Center domain node */}
        <circle
          cx={centerX}
          cy={centerY}
          r="30"
          fill="#f8fafc"
          stroke="#f97316"
          strokeWidth="3"
          className="transition-all duration-300"
        />
        <text
          x={centerX}
          y={centerY}
          textAnchor="middle"
          dy="0.3em"
          className="text-xs font-bold fill-slate-900"
        >
          Domain
        </text>

        {/* Security test nodes */}
        {nodes.map((node) => {
          const nodeColor = getNodeColor(node.status)
          const isScanning = node.status === "scanning"
          const isComplete = node.status === "complete"

          // Calculate progress ring properties
          const progressRadius = 24
          const circumference = 2 * Math.PI * progressRadius
          const progressOffset = isComplete ? 0 : circumference

          return (
            <g key={node.id}>
              {/* Background ring for progress */}
              <circle
                cx={node.x}
                cy={node.y}
                r={progressRadius}
                fill="none"
                stroke="#e2e8f0"
                strokeWidth="3"
                opacity="0.3"
              />

              {/* Animated progress ring */}
              <circle
                cx={node.x}
                cy={node.y}
                r={progressRadius}
                fill="none"
                stroke={nodeColor}
                strokeWidth="3"
                strokeDasharray={circumference}
                strokeDashoffset={progressOffset}
                strokeLinecap="round"
                className="transition-all duration-1000 ease-out"
                transform={`rotate(-90 ${node.x} ${node.y})`}
                opacity={node.status === "idle" ? 0 : 0.8}
              />

              {/* Node circle with gradient */}
              <circle
                cx={node.x}
                cy={node.y}
                r="20"
                fill={isScanning ? "url(#nodeGradient)" : nodeColor}
                stroke={nodeColor}
                strokeWidth="2"
                filter={isScanning ? "url(#glow)" : "url(#shadow)"}
                className={`transition-all duration-300 ${
                  isScanning ? "animate-pulse" : ""
                }`}
                opacity={node.status === "idle" ? 0.5 : 1}
              />

              {/* Status icon (checkmark or X) */}
              {node.status !== "idle" && node.status !== "scanning" && (
                <foreignObject
                  x={node.x - 10}
                  y={node.y - 10}
                  width="20"
                  height="20"
                >
                  <div className="flex items-center justify-center w-full h-full text-white">
                    {getStatusIcon(node.status)}
                  </div>
                </foreignObject>
              )}

              {/* Test name label with better styling */}
              <text
                x={node.x}
                y={node.y + 40}
                textAnchor="middle"
                className={`text-[11px] font-semibold ${
                  node.status === "scanning"
                    ? "fill-orange-600"
                    : node.status === "complete"
                    ? "fill-emerald-600"
                    : "fill-slate-500"
                }`}
              >
                {node.name}
              </text>
            </g>
          )
        })}
      </svg>
    </div>
  )
}
