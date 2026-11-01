"use client"

import { useState, useEffect } from "react"
import { CheckCircle } from "lucide-react"
import { NetworkGraph } from "./scan-dashboard/NetworkGraph"
import { MetricCard } from "./scan-dashboard/MetricCard"
import { ScanPhaseIndicator } from "./scan-dashboard/ScanPhaseIndicator"
import type { DashboardState, ScanPhase } from "./scan-dashboard/types"

interface InteractiveScanDashboardProps {
  onComplete?: () => void
}

// Timed phases for the animation only; they do not track the real scan
const SCAN_PHASES: ScanPhase[] = [
  {
    name: "Network Discovery",
    tests: ["dns", "spf"],
    duration: 6000,
  },
  {
    name: "Security Analysis",
    tests: ["ssl", "dmarc", "waf"],
    duration: 6000,
  },
  {
    name: "Defense Scanning",
    tests: ["headers", "blacklist"],
    duration: 6000,
  },
  {
    name: "Privacy",
    tests: ["compliance"],
    duration: 4500,
  },
  {
    name: "Score Calculation",
    tests: ["score"],
    duration: 1500,
  },
]

const TOTAL_TESTS = SCAN_PHASES.reduce((sum, phase) => sum + phase.tests.length, 0)

const initialState: DashboardState = {
  currentPhaseIndex: 0,
  completedTests: [],
  activeTests: [],
}

export function InteractiveScanDashboard({ onComplete }: InteractiveScanDashboardProps) {
  const [state, setState] = useState<DashboardState>(initialState)
  const [progressPercentage, setProgressPercentage] = useState(0)

  // Main animation orchestrator. Cleanup clears every pending timer, so a
  // re-run (StrictMode mounts effects twice in development) starts over.
  useEffect(() => {
    const timers: ReturnType<typeof setTimeout>[] = []
    let phaseIndex = 0
    const totalDuration = SCAN_PHASES.reduce((sum, phase) => sum + phase.duration, 0)
    let elapsedTime = 0

    const runPhase = () => {
      if (phaseIndex >= SCAN_PHASES.length) {
        // All phases complete
        return
      }

      const phase = SCAN_PHASES[phaseIndex]

      // Mark tests as active (multiple at once for dynamic effect)
      setState((prev) => ({
        ...prev,
        currentPhaseIndex: phaseIndex,
        activeTests: phase.tests,
      }))

      const timer = setTimeout(() => {
        // Mark tests as complete
        setState((prev) => ({
          ...prev,
          completedTests: [...prev.completedTests, ...phase.tests],
          activeTests: [],
        }))

        elapsedTime += phase.duration
        setProgressPercentage(Math.round((elapsedTime / totalDuration) * 100))

        phaseIndex++
        runPhase()
      }, phase.duration)

      timers.push(timer)
    }

    runPhase()

    return () => timers.forEach(clearTimeout)
  }, [])

  // Call onComplete when progress reaches 100%
  useEffect(() => {
    if (progressPercentage === 100 && onComplete) {
      const timer = setTimeout(() => onComplete(), 500)
      return () => clearTimeout(timer)
    }
  }, [progressPercentage, onComplete])

  const currentPhase = SCAN_PHASES[state.currentPhaseIndex]

  return (
    <div className="mt-6 py-8 space-y-6 animate-in fade-in duration-500">
      {/* Progress Header */}
      <div className="space-y-2">
        <div className="flex items-center justify-between text-sm">
          <span className="font-medium text-slate-700">Scanning Progress</span>
          <span className="text-slate-600">{progressPercentage}%</span>
        </div>
        <div className="h-2 w-full bg-slate-200 rounded-full overflow-hidden">
          <div
            className="h-full bg-gradient-to-r from-orange-500 to-amber-500 transition-all duration-300 ease-out"
            style={{ width: `${progressPercentage}%` }}
          />
        </div>
      </div>

      {/* Main Dashboard Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Network Graph: 2 columns on desktop */}
        <div className="md:col-span-2 order-2 md:order-1">
          <NetworkGraph
            completedTests={state.completedTests}
            activeTests={state.activeTests}
          />
        </div>

        {/* Metrics Sidebar: 1 column on desktop */}
        <div className="space-y-4 order-1 md:order-2">
          <MetricCard
            label="Tests Completed"
            value={`${state.completedTests.length}/${TOTAL_TESTS}`}
            icon={CheckCircle}
          />
        </div>
      </div>

      {/* Phase Indicator */}
      {currentPhase && <ScanPhaseIndicator phase={currentPhase} />}

      {/* Footer message */}
      <p className="text-xs text-slate-400 text-center">
        This may take 10-30 seconds depending on your domain configuration
      </p>
    </div>
  )
}
