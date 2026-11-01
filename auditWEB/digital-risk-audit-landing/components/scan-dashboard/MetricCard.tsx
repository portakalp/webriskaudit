"use client"

import type { LucideIcon } from "lucide-react"
import { useAnimatedCounter } from "./LiveCounter"

interface MetricCardProps {
  label: string
  value: number | string
  icon: LucideIcon
  animated?: boolean
  highlight?: boolean
  maxValue?: number
}

export function MetricCard({
  label,
  value,
  icon: Icon,
  animated = false,
  highlight = false,
  maxValue,
}: MetricCardProps) {
  // Use animated counter for numeric values when animated=true
  const numericValue = typeof value === "number" ? value : 0
  const displayValue = animated
    ? useAnimatedCounter(numericValue, 800)
    : value

  // Format the display value
  const formattedValue =
    typeof displayValue === "number"
      ? maxValue
        ? `${displayValue}/${maxValue}`
        : displayValue.toLocaleString()
      : displayValue

  return (
    <div
      className={`rounded-xl p-4 transition-all duration-300 ${
        highlight
          ? "bg-red-50 border-2 border-red-200 hover:shadow-lg"
          : "bg-slate-50 border-2 border-slate-200 hover:shadow-md"
      }`}
    >
      <div className="flex items-center justify-between mb-2">
        <Icon
          className={`w-5 h-5 ${
            highlight ? "text-red-600" : "text-slate-600"
          }`}
        />
        <span className="text-xs text-slate-500">{label}</span>
      </div>
      <div
        className={`text-2xl font-bold ${
          highlight ? "text-red-900" : "text-slate-900"
        }`}
      >
        {formattedValue}
      </div>
    </div>
  )
}
