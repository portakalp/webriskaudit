import { CircleCheck, CircleHelp, CircleX, Info, TriangleAlert, type LucideIcon } from "lucide-react"
import { STATUS_LABELS } from "@/lib/report"
import type { Status } from "@/lib/types"

// Every status has its own icon and text, so it never depends on colour alone.
const STYLES: Record<Status, { Icon: LucideIcon; className: string }> = {
  pass: { Icon: CircleCheck, className: "bg-emerald-50 text-emerald-800 ring-emerald-700/25" },
  warn: { Icon: TriangleAlert, className: "bg-amber-50 text-amber-900 ring-amber-700/30" },
  fail: { Icon: CircleX, className: "bg-red-50 text-red-800 ring-red-700/25" },
  inconclusive: { Icon: CircleHelp, className: "bg-slate-100 text-slate-700 ring-slate-500/30" },
  info: { Icon: Info, className: "bg-sky-50 text-sky-800 ring-sky-700/25" },
}

export function StatusBadge({ status, className = "" }: { status: Status; className?: string }) {
  const { Icon, className: colors } = STYLES[status]
  return (
    <span
      className={`inline-flex shrink-0 items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-semibold ring-1 ring-inset ${colors} ${className}`}
    >
      <Icon className="h-3.5 w-3.5" aria-hidden="true" />
      {STATUS_LABELS[status]}
    </span>
  )
}
