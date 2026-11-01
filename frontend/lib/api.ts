import type { ProblemDetails, ScanReport, ScanRequest } from "./types"

export const SCAN_PATH = "/api/v1/scan"

// The API gives up on a scan after 45 seconds, and a scan may first wait for
// a free slot; this client-side limit only catches a hung connection.
export const SCAN_TIMEOUT_MS = 90_000

export const GENERIC_ERROR = "Something went wrong while scanning. Please try again later."
export const UNREACHABLE_ERROR = "The scanner API could not be reached."

/**
 * Base URL of the API without a trailing slash. NEXT_PUBLIC_API_URL is inlined
 * at build time; without it, only development builds fall back to a local
 * API, so a production build never sends visitors' requests to localhost.
 */
export function apiBaseUrl(): string {
  const configured =
    process.env.NEXT_PUBLIC_API_URL || (process.env.NODE_ENV === "development" ? "http://localhost:8000" : "")
  return configured.replace(/\/+$/, "")
}

/** An error whose message is safe to show to the user. */
export class ScanError extends Error {
  override name = "ScanError"
}

/** The API refused the scan with RFC 9457 problem details. */
export class ApiProblemError extends ScanError {
  override name = "ApiProblemError"
  readonly type: string
  readonly title: string
  readonly detail: string
  readonly status: number
  /** Seconds until another scan is allowed (from Retry-After), or null. */
  readonly retryAfterSeconds: number | null

  constructor(problem: ProblemDetails, message: string = problem.detail, retryAfterSeconds: number | null = null) {
    super(message)
    this.type = problem.type
    this.title = problem.title
    this.detail = problem.detail
    this.status = problem.status
    this.retryAfterSeconds = retryAfterSeconds
  }
}

/**
 * Runs POST /api/v1/scan. Rejects with a ScanError (an ApiProblemError when
 * the API explains the refusal) on timeout, network failure or a non-2xx
 * response. If `signal` aborts, the original AbortError is rethrown so the
 * caller can ignore it.
 */
export async function scanDomain(domain: string, signal?: AbortSignal): Promise<ScanReport> {
  const baseUrl = apiBaseUrl()
  if (!baseUrl) {
    throw new ScanError("The scanner API is not available right now.")
  }

  const controller = new AbortController()
  let timedOut = false
  const timeout = setTimeout(() => {
    timedOut = true
    controller.abort()
  }, SCAN_TIMEOUT_MS)
  const cancel = () => controller.abort()
  if (signal?.aborted) cancel()
  signal?.addEventListener("abort", cancel)

  try {
    const body: ScanRequest = { domain }
    const response = await fetch(`${baseUrl}${SCAN_PATH}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal: controller.signal,
    })

    if (!response.ok) {
      throw await responseError(response)
    }

    const report: unknown = await response.json()
    if (!isScanReport(report)) {
      throw new ScanError("The scanner API sent a response this page cannot read.")
    }
    return report
  } catch (err) {
    if (err instanceof ScanError || signal?.aborted) {
      throw err
    }
    if (timedOut) {
      throw new ScanError(
        `The scan did not finish within ${SCAN_TIMEOUT_MS / 1000} seconds. Please try again later.`,
      )
    }
    if (err instanceof TypeError) {
      // fetch() rejects with a TypeError for network and CORS failures
      throw new ScanError(UNREACHABLE_ERROR)
    }
    throw new ScanError(GENERIC_ERROR)
  } finally {
    clearTimeout(timeout)
    signal?.removeEventListener("abort", cancel)
  }
}

/** Loads public/sample-report.json. Rejects with a ScanError on any failure. */
export async function loadSampleReport(): Promise<ScanReport> {
  try {
    const response = await fetch("/sample-report.json")
    if (response.ok) {
      const report: unknown = await response.json()
      if (isScanReport(report)) {
        return report
      }
    }
  } catch {
    // Network or parse failure, reported below
  }
  throw new ScanError("The sample report could not be loaded.")
}

/**
 * Seconds to wait from a Retry-After value: delay-seconds or an HTTP date
 * (RFC 9110, section 10.2.3). Null if the value is missing or unreadable.
 */
export function parseRetryAfter(value: string | null, now: number = Date.now()): number | null {
  const text = value?.trim()
  if (!text) return null
  if (/^\d+$/.test(text)) return Number(text)
  const date = Date.parse(text)
  return Number.isNaN(date) ? null : Math.max(0, Math.ceil((date - now) / 1000))
}

/** "45 seconds", "1 minute", "5 minutes" */
export function formatWait(seconds: number): string {
  if (seconds < 120) return seconds === 1 ? "1 second" : `${seconds} seconds`
  return `${Math.ceil(seconds / 60)} minutes`
}

async function responseError(response: Response): Promise<ScanError> {
  const problem = await readProblem(response)
  const wait = parseRetryAfter(response.headers.get("Retry-After"))
  if (problem) {
    // The API's detail is written for users and already names the reason and the wait.
    return new ApiProblemError(problem, problem.detail, wait)
  }
  if (response.status === 429) {
    const message =
      wait === null
        ? "Too many scans from this address. Please try again later."
        : `Too many scans from this address. Try again in ${formatWait(wait)}.`
    const details = { type: "about:blank", title: "Too many scans", status: 429, detail: message }
    return new ApiProblemError(details, message, wait)
  }
  if (response.status >= 500) {
    return new ScanError(`The scanner API failed (HTTP ${response.status}). Please try again later.`)
  }
  return new ScanError(GENERIC_ERROR)
}

/** The problem details in an application/problem+json body, or null. */
async function readProblem(response: Response): Promise<ProblemDetails | null> {
  const contentType = response.headers.get("Content-Type") ?? ""
  if (!/^application\/problem\+json\s*(;|$)/i.test(contentType)) return null

  const body: unknown = await response.json().catch(() => null)
  if (!isRecord(body) || typeof body.title !== "string" || typeof body.detail !== "string") {
    return null
  }
  return {
    type: typeof body.type === "string" ? body.type : "about:blank",
    title: body.title,
    detail: body.detail,
    status: typeof body.status === "number" ? body.status : response.status,
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
}

/** A shallow shape check, enough to render the report without crashing. */
function isScanReport(value: unknown): value is ScanReport {
  return (
    isRecord(value) &&
    typeof value.domain === "string" &&
    isRecord(value.coverage) &&
    Array.isArray(value.categories) &&
    Array.isArray(value.checks)
  )
}
