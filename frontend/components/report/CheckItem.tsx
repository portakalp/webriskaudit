"use client"

import { ChevronDown, ExternalLink } from "lucide-react"
import { StatusBadge } from "./StatusBadge"
import { formatDuration, formatPoints, isHttpUrl } from "@/lib/report"
import type { CheckResult } from "@/lib/types"

interface CheckItemProps {
  check: CheckResult
  open: boolean
  onToggle: (id: string) => void
}

/** One check: status, title and summary, with a disclosure for the evidence. */
export function CheckItem({ check, open, onToggle }: CheckItemProps) {
  const evidence = check.evidence ?? []
  const references = (check.references ?? []).filter((reference) => isHttpUrl(reference.url))
  const domId = `check-${check.id.replace(/[^a-zA-Z0-9_-]/g, "-")}`
  const summaryId = `${domId}-summary`
  const panelId = `${domId}-details`

  return (
    <li className="py-4 first:pt-0 last:pb-0">
      <h4 className="text-base font-semibold text-slate-900">
        <button
          type="button"
          aria-expanded={open}
          aria-controls={panelId}
          aria-describedby={summaryId}
          onClick={() => onToggle(check.id)}
          className="group flex w-full flex-wrap items-center gap-x-3 gap-y-2 rounded-lg text-left sm:flex-nowrap"
        >
          {/* The space keeps "Pass" and the title apart in the accessible name */}
          <StatusBadge status={check.status} className="sm:w-32 sm:justify-center" />{" "}
          <span className="min-w-0 flex-1 group-hover:underline">{check.title}</span>
          <span className="flex items-center gap-1 text-xs font-medium text-slate-600" aria-hidden="true">
            {open ? "Hide" : "Details"}
            <ChevronDown className={`h-4 w-4 transition-transform ${open ? "rotate-180" : ""}`} />
          </span>
        </button>
      </h4>
      <p id={summaryId} className="mt-1.5 max-w-3xl text-sm text-slate-700 sm:pl-35">
        {check.summary}
      </p>

      <div
        id={panelId}
        hidden={!open}
        className="mt-3 space-y-4 rounded-xl border border-slate-200 bg-slate-50 p-4 text-sm sm:ml-35"
      >
        {evidence.length > 0 ? (
          <section>
            <h5 className="text-xs font-semibold uppercase tracking-wide text-slate-600">Evidence</h5>
            <dl className="mt-1 divide-y divide-slate-200">
              {evidence.map((item, index) => (
                <div
                  key={`${index}-${item.label}`}
                  className="grid gap-1 py-2 sm:grid-cols-[minmax(0,13rem)_minmax(0,1fr)] sm:gap-4"
                >
                  <dt className="font-medium text-slate-700">{item.label}</dt>
                  <dd className="font-mono text-[13px] text-slate-900 [overflow-wrap:anywhere]">{item.value}</dd>
                </div>
              ))}
            </dl>
          </section>
        ) : (
          <p className="text-slate-700">No evidence was recorded for this check.</p>
        )}

        {check.remediation && (
          <section>
            <h5 className="text-xs font-semibold uppercase tracking-wide text-slate-600">How to fix</h5>
            <p className="mt-1 max-w-3xl text-slate-800">{check.remediation}</p>
          </section>
        )}

        {references.length > 0 && (
          <section>
            <h5 className="text-xs font-semibold uppercase tracking-wide text-slate-600">References</h5>
            <ul className="mt-1 space-y-1">
              {references.map((reference) => (
                <li key={reference.url}>
                  <a
                    href={reference.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="rounded text-orange-800 underline underline-offset-2 hover:text-orange-900"
                  >
                    {reference.title}
                    <ExternalLink className="ml-1 inline-block h-3.5 w-3.5 align-[-2px]" aria-hidden="true" />
                    <span className="sr-only"> (opens in a new tab)</span>
                  </a>
                </li>
              ))}
            </ul>
          </section>
        )}

        <p className="text-xs text-slate-600">
          {scoreNote(check)} · took {formatDuration(check.duration_ms)} · <code>{check.id}</code>
        </p>
      </div>
    </li>
  )
}

function scoreNote({ weight, points, status }: CheckResult): string {
  if (weight === 0) return "Informational, not scored"
  if (status === "inconclusive") return `Left out of the score (worth ${weight} points)`
  return `${formatPoints(points)} of ${weight} points`
}
