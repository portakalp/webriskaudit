import type { ScanResult } from "./types"

// Inlined at build time. Without it, only development builds fall back to a
// local API, so a production build never sends visitors' requests to localhost.
const API_URL = (
  process.env.NEXT_PUBLIC_API_URL ||
  (process.env.NODE_ENV === "development" ? "http://localhost:8000" : "")
).replace(/\/+$/, "")

const SCAN_TIMEOUT_MS = 60_000

const GENERIC_ERROR = "Something went wrong while scanning. Please try again later."

// An error whose message is safe to show to the user
export class ScanError extends Error {
  name = "ScanError"
}

async function errorMessage(response: Response): Promise<string> {
  if (response.status === 422) {
    return "That doesn't look like a valid domain."
  }
  if (response.status === 502) {
    const body: unknown = await response.json().catch(() => null)
    if (typeof body === "object" && body !== null && "detail" in body && typeof body.detail === "string") {
      return body.detail
    }
  }
  return GENERIC_ERROR
}

/**
 * Runs POST /api/scan. Rejects with a ScanError on timeout, network failure
 * or a non-2xx response. If `signal` aborts, the original AbortError is
 * rethrown so the caller can ignore it.
 */
export async function scanDomain(domain: string, signal?: AbortSignal): Promise<ScanResult> {
  if (!API_URL) {
    throw new ScanError("The scanner API is not available right now.")
  }

  const controller = new AbortController()
  const timeout = setTimeout(() => controller.abort(), SCAN_TIMEOUT_MS)
  const cancel = () => controller.abort()
  signal?.addEventListener("abort", cancel)

  try {
    const response = await fetch(`${API_URL}/api/scan`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ domain }),
      signal: controller.signal,
    })

    if (!response.ok) {
      throw new ScanError(await errorMessage(response))
    }

    return (await response.json()) as ScanResult
  } catch (err) {
    if (err instanceof ScanError || signal?.aborted) {
      throw err
    }
    if (controller.signal.aborted) {
      throw new ScanError("The scan did not finish within 60 seconds. Please try again later.")
    }
    if (err instanceof TypeError) {
      throw new ScanError("The scanner API could not be reached. It may be offline.")
    }
    throw new ScanError(GENERIC_ERROR)
  } finally {
    clearTimeout(timeout)
    signal?.removeEventListener("abort", cancel)
  }
}

export async function loadSampleReport(): Promise<ScanResult> {
  const response = await fetch("/sample-report.json")
  if (!response.ok) {
    throw new ScanError("The sample report could not be loaded.")
  }

  // "_placeholder" only tells maintainers the file still holds made-up values
  const report: ScanResult & { _placeholder?: boolean } = await response.json()
  delete report._placeholder
  return report
}
