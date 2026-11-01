"use client"

import { Loader2 } from "lucide-react"
import type { ScanPhase } from "./types"

interface ScanPhaseIndicatorProps {
  phase: ScanPhase
}

export function ScanPhaseIndicator({ phase }: ScanPhaseIndicatorProps) {
  return (
    <div className="text-center p-4 bg-slate-50 rounded-lg border-2 border-slate-200 animate-in fade-in duration-300">
      <div className="flex items-center justify-center gap-2">
        <Loader2 className="w-4 h-4 animate-spin text-orange-500" />
        <span className="text-sm font-medium text-slate-700">
          {phase.name}
        </span>
      </div>
    </div>
  )
}
