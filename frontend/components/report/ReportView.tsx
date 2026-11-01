"use client"

import { useEffect, useMemo, useRef, useState, type ReactNode } from "react"
import { Download, RotateCcw } from "lucide-react"
import { CheckItem } from "./CheckItem"
import { StatusBadge } from "./StatusBadge"
import {
  countStatuses,
  coverageText,
  formatDuration,
  formatPoints,
  groupChecks,
  scoreTone,
  type Tone,
} from "@/lib/report"
import type { CategorySummary, ScanReport, Status } from "@/lib/types"

const STATUS_ORDER: Status[] = ["pass", "warn", "fail", "inconclusive", "info"]

const TONE_PANEL: Record<Tone, string> = {
  good: "border-emerald-200 bg-emerald-50 text-emerald-900",
  fair: "border-amber-200 bg-amber-50 text-amber-900",
  poor: "border-red-200 bg-red-50 text-red-900",
  none: "border-slate-200 bg-slate-100 text-slate-800",
}

const TONE_BAR: Record<Tone, string> = {
  good: "bg-emerald-600",
  fair: "bg-amber-500",
  poor: "bg-red-600",
  none: "bg-slate-400",
}

const SECONDARY_BUTTON =
  "flex flex-1 items-center justify-center gap-2 rounded-xl border-2 border-slate-200 bg-white px-6 py-3 text-sm font-semibold text-slate-800 transition-colors hover:border-slate-300 hover:bg-slate-50"

interface ReportViewProps {
  report: ScanReport
  onReset: () => void
}

export function ReportView({ report, onReset }: ReportViewProps) {
  const headingRef = useRef<HTMLHeadingElement>(null)
  const groups = useMemo(() => groupChecks(report), [report])
  const counts = useMemo(() => countStatuses(report.checks), [report])
  const [openIds, setOpenIds] = useState<ReadonlySet<string>>(() => new Set())
  const allOpen = report.checks.length > 0 && openIds.size === report.checks.length

  // Start keyboard and screen reader users at the top of the new report
  useEffect(() => {
    headingRef.current?.focus()
  }, [])

  const toggle = (id: string) =>
    setOpenIds((previous) => {
      const next = new Set(previous)
      if (!next.delete(id)) next.add(id)
      return next
    })

  const toggleAll = () => setOpenIds(allOpen ? new Set() : new Set(report.checks.map((check) => check.id)))

  return (
    <article aria-labelledby="report-heading" className="space-y-8">
      <header className="flex flex-col gap-6 md:flex-row md:items-center md:justify-between">
        <div className="min-w-0 space-y-3">
          <h2 id="report-heading" ref={headingRef} tabIndex={-1} className="outline-none">
            <span className="block text-xs font-semibold uppercase tracking-[0.15em] text-slate-600">
              Security posture report
            </span>
            <span className="mt-2 block text-2xl font-bold text-slate-900 [overflow-wrap:anywhere] md:text-3xl">
              {report.domain}
            </span>
          </h2>
          <p className="text-sm text-slate-700">{coverageText(report.coverage)}</p>
          <ul aria-label="Results by status" className="flex flex-wrap gap-x-4 gap-y-2">
            {STATUS_ORDER.filter((status) => counts[status] > 0).map((status) => (
              <li key={status} className="flex items-center gap-1.5 text-sm font-semibold text-slate-900">
                <StatusBadge status={status} /> {counts[status]}
              </li>
            ))}
          </ul>
        </div>
        <ScorePanel score={report.score} grade={report.grade} />
      </header>

      <section aria-labelledby="categories-heading">
        <h3 id="categories-heading" className="text-lg font-bold text-slate-900">
          Categories
        </h3>
        <ul className="mt-3 grid gap-3 sm:grid-cols-3">
          {report.categories.map((category) => (
            <CategoryCard key={category.id} category={category} />
          ))}
        </ul>
      </section>

      <div className="space-y-8">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <p className="text-sm text-slate-700">
            {report.checks.length} checks. Open a check to see its evidence, how to fix it and references.
          </p>
          <button
            type="button"
            onClick={toggleAll}
            className="rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-sm font-medium text-slate-800 hover:bg-slate-50"
          >
            {allOpen ? "Hide all details" : "Show all details"}
          </button>
        </div>

        {groups.map((group) => (
          <section
            key={group.id}
            id={`group-${group.id}`}
            aria-labelledby={`group-${group.id}-heading`}
            className="scroll-mt-6"
          >
            <div className="flex flex-wrap items-baseline justify-between gap-2 border-b border-slate-200 pb-2">
              <h3 id={`group-${group.id}-heading`} className="text-lg font-bold text-slate-900">
                {group.title}
              </h3>
              <p className="text-sm text-slate-700">{groupNote(group.summary)}</p>
            </div>
            <ul className="mt-4 divide-y divide-slate-200">
              {group.checks.map((check) => (
                <CheckItem key={check.id} check={check} open={openIds.has(check.id)} onToggle={toggle} />
              ))}
            </ul>
          </section>
        ))}
      </div>

      <footer className="space-y-4 border-t border-slate-200 pt-6 text-xs text-slate-600">
        <dl className="flex flex-wrap gap-x-6 gap-y-2">
          <Meta label="Scanned">
            <time dateTime={report.scanned_at}>{formatScanTime(report.scanned_at)}</time>
          </Meta>
          <Meta label="Duration">{formatDuration(report.duration_ms)}</Meta>
          <Meta label="Scanner">{report.scanner_version}</Meta>
          <Meta label="Methodology">{report.methodology_version}</Meta>
        </dl>
        <p className="max-w-3xl text-pretty">
          These results come from automated, heuristic checks and can be incomplete or wrong. Inconclusive checks
          are left out of the score. They are not a substitute for a professional security assessment.
        </p>
      </footer>

      <div className="flex flex-col gap-3 sm:flex-row">
        <button type="button" onClick={onReset} className={SECONDARY_BUTTON}>
          <RotateCcw className="h-4 w-4" aria-hidden="true" />
          Scan another domain
        </button>
        <button type="button" onClick={() => downloadJson(report)} className={SECONDARY_BUTTON}>
          <Download className="h-4 w-4" aria-hidden="true" />
          Download JSON
        </button>
      </div>
    </article>
  )
}

function ScorePanel({ score, grade }: Pick<ScanReport, "score" | "grade">) {
  const tone = scoreTone(score)
  if (score === null) {
    return (
      <div className={`rounded-2xl border-2 p-5 md:w-72 ${TONE_PANEL[tone]}`}>
        <p className="text-lg font-bold">Not enough data for a score</p>
        <p className="mt-1 text-sm">Checks worth less than half of the points reached a verdict.</p>
      </div>
    )
  }
  return (
    <div className={`flex items-center gap-5 rounded-2xl border-2 px-6 py-5 md:w-72 ${TONE_PANEL[tone]}`}>
      <p className="text-center">
        <span className="block text-xs font-semibold uppercase tracking-wide">Grade</span>
        <span className="block text-5xl font-bold leading-none">{grade}</span>
      </p>
      <p>
        <span className="block text-xs font-semibold uppercase tracking-wide">Score</span>
        <span className="text-4xl font-bold leading-none">{score}</span>
        <span className="text-lg font-semibold" aria-hidden="true">
          /100
        </span>
        <span className="sr-only"> out of 100</span>
      </p>
    </div>
  )
}

function CategoryCard({ category }: { category: CategorySummary }) {
  const tone = scoreTone(category.score)
  return (
    <li className="rounded-xl border border-slate-200 bg-white p-4">
      <a
        href={`#group-${category.id}`}
        className="text-sm font-semibold text-slate-900 underline-offset-2 hover:underline"
      >
        {category.title}
      </a>
      <p className="mt-2 text-2xl font-bold text-slate-900">
        {category.score === null ? (
          "No data"
        ) : (
          <>
            {category.score}
            <span className="text-sm font-semibold text-slate-600" aria-hidden="true">
              /100
            </span>
            <span className="sr-only"> out of 100</span>
          </>
        )}
      </p>
      <div className="mt-2 h-2 overflow-hidden rounded-full bg-slate-200" aria-hidden="true">
        <div className={`h-full rounded-full ${TONE_BAR[tone]}`} style={{ width: `${category.score ?? 0}%` }} />
      </div>
      <p className="mt-2 text-xs text-slate-600">
        {category.possible > 0
          ? `${formatPoints(category.points)} of ${category.possible} points from completed checks`
          : "No check in this category reached a verdict"}
      </p>
    </li>
  )
}

function Meta({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex gap-1.5">
      <dt className="font-semibold text-slate-700">{label}</dt>
      <dd>{children}</dd>
    </div>
  )
}

function groupNote(summary: CategorySummary | null): string {
  if (!summary) return "Not scored"
  return summary.score === null ? "No score" : `${summary.score}/100`
}

const SCAN_TIME_FORMAT = new Intl.DateTimeFormat("en-GB", {
  year: "numeric",
  month: "short",
  day: "numeric",
  hour: "2-digit",
  minute: "2-digit",
  timeZoneName: "short",
})

function formatScanTime(iso: string): string {
  const date = new Date(iso)
  return Number.isNaN(date.getTime()) ? iso : SCAN_TIME_FORMAT.format(date)
}

function downloadJson(report: ScanReport) {
  const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" })
  const url = URL.createObjectURL(blob)
  const link = document.createElement("a")
  link.href = url
  link.download = `webriskaudit-${report.domain}-${report.scanned_at.slice(0, 10)}.json`
  link.click()
  setTimeout(() => URL.revokeObjectURL(url), 0)
}
