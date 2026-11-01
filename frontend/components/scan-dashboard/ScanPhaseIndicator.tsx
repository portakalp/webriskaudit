import { LoaderCircle } from "lucide-react"

export function ScanPhaseIndicator({ label }: { label: string }) {
  return (
    <div className="flex items-center justify-center gap-2 rounded-lg border-2 border-slate-200 bg-slate-50 p-4">
      <LoaderCircle className="h-4 w-4 text-orange-700 motion-safe:animate-spin" aria-hidden="true" />
      <span className="text-sm font-medium text-slate-800">{label}</span>
    </div>
  )
}
