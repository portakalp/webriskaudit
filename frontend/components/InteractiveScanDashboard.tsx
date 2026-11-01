"use client"

import { useEffect, useMemo, useState } from "react"
import { NetworkGraph } from "./scan-dashboard/NetworkGraph"
import { ScanPhaseIndicator } from "./scan-dashboard/ScanPhaseIndicator"
import type { ScanPhase } from "./scan-dashboard/types"

// An animation, not live progress: the API runs all checks at the same time
// and answers once, with the whole report. These phases only play on a timer.
// The parent replaces this view as soon as the API responds, usually before
// the phases have played out; if the scan takes longer, the last phase stays.
const PHASES: ScanPhase[] = [
  { label: "Looking up SPF, DMARC and DKIM records", nodes: ["spf", "dmarc", "dkim"], duration: 1200 },
  { label: "Reading the TLS certificate", nodes: ["tls"], duration: 900 },
  { label: "Following the HTTP to HTTPS redirect", nodes: ["redirect", "hsts"], duration: 1000 },
  {
    label: "Reading the home page's security headers",
    nodes: ["csp", "frames", "nosniff", "referrer", "cookies", "server"],
    duration: 1500,
  },
  {
    label: "Noting the CDN, privacy link and other headers",
    nodes: ["cdn", "privacy", "permissions", "deprecated"],
    duration: 1200,
  },
  { label: "Waiting for the scan to finish", nodes: [], duration: 0 },
]

export function InteractiveScanDashboard({ domain }: { domain: string }) {
  const [phaseIndex, setPhaseIndex] = useState(0)
  const [elapsedSeconds, setElapsedSeconds] = useState(0)

  // Step through the phases once; cleanup clears the timer, so a re-run
  // (StrictMode runs effects twice in development) does not skip a phase.
  useEffect(() => {
    if (phaseIndex >= PHASES.length - 1) return
    const timer = setTimeout(() => setPhaseIndex((index) => index + 1), PHASES[phaseIndex].duration)
    return () => clearTimeout(timer)
  }, [phaseIndex])

  // Real elapsed time, the one honest progress figure on this view
  useEffect(() => {
    const started = Date.now()
    const timer = setInterval(() => setElapsedSeconds(Math.floor((Date.now() - started) / 1000)), 1000)
    return () => clearInterval(timer)
  }, [])

  const completed = useMemo(() => new Set(PHASES.slice(0, phaseIndex).flatMap((phase) => phase.nodes)), [phaseIndex])
  const active = useMemo(() => new Set(PHASES[phaseIndex].nodes), [phaseIndex])

  return (
    <div className="mt-6 space-y-5 animate-in fade-in duration-500">
      <div className="flex items-baseline justify-between gap-4">
        <p className="min-w-0 text-sm font-semibold text-slate-900">
          Scanning <span className="font-mono [overflow-wrap:anywhere]">{domain}</span>
        </p>
        <p className="shrink-0 text-xs tabular-nums text-slate-600">{elapsedSeconds} s elapsed</p>
      </div>

      <NetworkGraph completed={completed} active={active} />

      <ScanPhaseIndicator label={PHASES[phaseIndex].label} />

      <p className="text-center text-xs text-slate-600 text-pretty">
        Most scans finish within a few seconds. A slow or unreachable site can take up to about 45 seconds, plus up
        to 30 seconds of waiting when the scanner is busy. The animation is illustrative: the checks run in parallel
        on the server.
      </p>
    </div>
  )
}
