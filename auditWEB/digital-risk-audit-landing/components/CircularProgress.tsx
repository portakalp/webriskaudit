"use client"

import { RadialBarChart, RadialBar, PolarAngleAxis } from "recharts"

interface CircularProgressProps {
  percentage: number
  size?: number
  strokeWidth?: number
  color?: string
}

export function CircularProgress({
  percentage,
  size = 120,
  strokeWidth = 10,
  color = "#10b981"
}: CircularProgressProps) {
  const data = [{ value: percentage, fill: color }]

  return (
    <div className="relative" style={{ width: size, height: size }}>
      <RadialBarChart
        width={size}
        height={size}
        cx={size / 2}
        cy={size / 2}
        innerRadius={size * 0.4}
        outerRadius={size * 0.5}
        barSize={strokeWidth}
        data={data}
        startAngle={90}
        endAngle={-270}
      >
        <PolarAngleAxis type="number" domain={[0, 100]} tick={false} />
        <RadialBar
          background={{ fill: "#e5e7eb" }}
          dataKey="value"
          cornerRadius={strokeWidth / 2}
          animationDuration={1000}
        />
      </RadialBarChart>

      <div className="absolute inset-0 flex items-center justify-center">
        <span className="text-2xl font-bold text-slate-900">
          {Math.round(percentage)}%
        </span>
      </div>
    </div>
  )
}
