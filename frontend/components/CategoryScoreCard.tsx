"use client"

import { CircularProgress } from "./CircularProgress"
import type { LucideIcon } from "lucide-react"

interface CategoryScoreCardProps {
  title: string
  icon: LucideIcon
  score: number
  max: number
  percentage: number
  riskLevel: "SECURE" | "MODERATE" | "CRITICAL"
}

export function CategoryScoreCard({
  title,
  icon: Icon,
  score,
  max,
  percentage,
  riskLevel
}: CategoryScoreCardProps) {
  const getColorByRisk = () => {
    if (riskLevel === "SECURE") return "#10b981"
    if (riskLevel === "MODERATE") return "#f59e0b"
    return "#ef4444"
  }

  const getBgByRisk = () => {
    if (riskLevel === "SECURE") return "bg-emerald-50 border-emerald-200"
    if (riskLevel === "MODERATE") return "bg-yellow-50 border-yellow-200"
    return "bg-red-50 border-red-200"
  }

  return (
    <div className={`p-4 rounded-xl border-2 ${getBgByRisk()} transition-all hover:shadow-md`}>
      <div className="flex flex-col items-center gap-3">
        <Icon className="w-6 h-6 text-slate-700" />
        <h4 className="text-sm font-semibold text-slate-900 text-center">{title}</h4>

        <CircularProgress
          percentage={percentage}
          color={getColorByRisk()}
          size={100}
        />

        <div className="text-center">
          <p className="text-xs text-slate-600">
            {score}/{max} points
          </p>
          <span className={`text-xs font-medium ${
            riskLevel === "SECURE" ? "text-emerald-700" :
            riskLevel === "MODERATE" ? "text-yellow-700" :
            "text-red-700"
          }`}>
            {riskLevel}
          </span>
        </div>
      </div>
    </div>
  )
}
