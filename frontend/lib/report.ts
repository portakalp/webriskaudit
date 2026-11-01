import type { Category, CategorySummary, CheckResult, Coverage, ScanReport, Status } from "./types"

export const STATUS_LABELS: Record<Status, string> = {
  pass: "Pass",
  warn: "Warning",
  fail: "Fail",
  inconclusive: "Inconclusive",
  info: "Info",
}

// The report only summarizes scored categories, so the informational group
// takes its title from here.
const CATEGORY_TITLES: Record<Category, string> = {
  email: "Email authentication",
  transport: "HTTPS and TLS",
  headers: "HTTP security headers",
  info: "Informational",
}

export interface CheckGroup {
  id: Category
  title: string
  summary: CategorySummary | null
  checks: CheckResult[]
}

/** Checks grouped by category, keeping the order in which the API lists them. */
export function groupChecks(report: ScanReport): CheckGroup[] {
  const groups = new Map<Category, CheckGroup>()
  for (const check of report.checks) {
    let group = groups.get(check.category)
    if (!group) {
      const summary = report.categories.find((category) => category.id === check.category) ?? null
      group = { id: check.category, title: summary?.title ?? CATEGORY_TITLES[check.category], summary, checks: [] }
      groups.set(check.category, group)
    }
    group.checks.push(check)
  }
  return [...groups.values()]
}

export function countStatuses(checks: CheckResult[]): Record<Status, number> {
  const counts: Record<Status, number> = { pass: 0, warn: 0, fail: 0, inconclusive: 0, info: 0 }
  for (const check of checks) counts[check.status] += 1
  return counts
}

/** "11 of 12 scored checks completed, 1 inconclusive" */
export function coverageText({ scored, total, inconclusive }: Coverage): string {
  return `${scored} of ${total} scored checks completed, ${inconclusive} inconclusive`
}

/** 27.5 -> "27.5", 30 -> "30" */
export function formatPoints(points: number): string {
  return Number.isInteger(points) ? String(points) : points.toFixed(1)
}

/** 512 -> "512 ms", 1530 -> "1.5 s" */
export function formatDuration(ms: number): string {
  return ms < 1000 ? `${ms} ms` : `${(ms / 1000).toFixed(1)} s`
}

export type Tone = "good" | "fair" | "poor" | "none"

/** Colour band for a 0-100 score; the boundaries follow grades B (75) and D (45). */
export function scoreTone(score: number | null): Tone {
  if (score === null) return "none"
  if (score >= 75) return "good"
  if (score >= 45) return "fair"
  return "poor"
}

/** Only http(s) links from the report are rendered as links. */
export function isHttpUrl(url: string): boolean {
  try {
    const { protocol } = new URL(url)
    return protocol === "https:" || protocol === "http:"
  } catch {
    return false
  }
}
