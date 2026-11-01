"use client"

import type { LucideIcon } from "lucide-react"

interface MetricCardProps {
  label: string
  value: string
  icon: LucideIcon
}

export function MetricCard({ label, value, icon: Icon }: MetricCardProps) {
  return (
    <div className="rounded-xl p-4 transition-all duration-300 bg-slate-50 border-2 border-slate-200 hover:shadow-md">
      <div className="flex items-center justify-between mb-2">
        <Icon className="w-5 h-5 text-slate-600" />
        <span className="text-xs text-slate-500">{label}</span>
      </div>
      <div className="text-2xl font-bold text-slate-900">{value}</div>
    </div>
  )
}
