// @vitest-environment node
import { beforeEach, describe, expect, it, vi } from "vitest"
import {
  ApiProblemError,
  SCAN_TIMEOUT_MS,
  ScanError,
  UNREACHABLE_ERROR,
  formatWait,
  loadSampleReport,
  parseRetryAfter,
  scanDomain,
} from "./api"
import { sampleReport as sample } from "@/test/sample-report"

const API_URL = "https://api.example.test"
function jsonResponse(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  })
}

function problemResponse(status: number, slug: string, title: string, detail: string, headers = {}): Response {
  const body = { type: `https://webriskaudit.com/problems/${slug}`, title, status, detail }
  return jsonResponse(body, status, { "Content-Type": "application/problem+json", ...headers })
}

/** A fetch that never answers and rejects like the real one when its signal aborts. */
function hangingFetch() {
  return vi.fn(
    (_url: string, init?: RequestInit) =>
      new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")))
      }),
  )
}

function mockFetch(implementation: () => Promise<Response>) {
  const fetchMock = vi.fn(implementation)
  vi.stubGlobal("fetch", fetchMock)
  return fetchMock
}

beforeEach(() => {
  vi.stubEnv("NEXT_PUBLIC_API_URL", `${API_URL}/`)
})

describe("scanDomain", () => {
  it("posts the domain to /api/v1/scan and returns the report", async () => {
    const fetchMock = mockFetch(async () => jsonResponse(sample))

    await expect(scanDomain("example.com")).resolves.toEqual(sample)

    expect(fetchMock).toHaveBeenCalledOnce()
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit]
    expect(url).toBe(`${API_URL}/api/v1/scan`)
    expect(init.method).toBe("POST")
    expect(init.headers).toEqual({ "Content-Type": "application/json" })
    expect(JSON.parse(init.body as string)).toEqual({ domain: "example.com" })
  })

  it("turns a 422 problem into an ApiProblemError with its title, detail and status", async () => {
    const detail = "nope.example.org does not exist in DNS (NXDOMAIN)."
    mockFetch(async () => problemResponse(422, "domain-not-found", "Domain not found", detail))

    const error = await scanDomain("nope.example.org").catch((err: unknown) => err)

    expect(error).toBeInstanceOf(ApiProblemError)
    expect(error).toMatchObject({
      type: "https://webriskaudit.com/problems/domain-not-found",
      title: "Domain not found",
      detail,
      status: 422,
      message: detail,
    })
  })

  it("shows the detail of a 429 problem and reads Retry-After", async () => {
    const detail = "Too many scans from this address. Try again in 42 seconds."
    mockFetch(async () =>
      problemResponse(429, "rate-limited", "Too many scans", detail, {
        "Retry-After": "42",
      }),
    )

    const error = await scanDomain("example.com").catch((err: unknown) => err)

    expect(error).toBeInstanceOf(ApiProblemError)
    expect(error).toMatchObject({
      status: 429,
      title: "Too many scans",
      retryAfterSeconds: 42,
      message: detail,
    })
  })

  it("keeps the reason of a 429 for a scan that is still running", async () => {
    const detail = "A scan from this address is still running. Try again when it has finished."
    mockFetch(async () => problemResponse(429, "rate-limited", "Too many scans", detail, { "Retry-After": "5" }))

    const error = await scanDomain("example.com").catch((err: unknown) => err)

    expect(error).toBeInstanceOf(ApiProblemError)
    expect(error).toMatchObject({ status: 429, retryAfterSeconds: 5, message: detail })
  })

  it("reads Retry-After from a 503 scanner-busy problem", async () => {
    const detail = "The scanner is busy with other scans. Try again in 10 seconds."
    mockFetch(async () => problemResponse(503, "scanner-busy", "Scanner busy", detail, { "Retry-After": "10" }))

    const error = await scanDomain("example.com").catch((err: unknown) => err)

    expect(error).toBeInstanceOf(ApiProblemError)
    expect(error).toMatchObject({ status: 503, title: "Scanner busy", retryAfterSeconds: 10, message: detail })
  })

  it("still explains a 429 without a problem body or Retry-After", async () => {
    mockFetch(async () => new Response("slow down", { status: 429, headers: { "Content-Type": "text/plain" } }))

    const error = await scanDomain("example.com").catch((err: unknown) => err)

    expect(error).toBeInstanceOf(ApiProblemError)
    expect(error).toMatchObject({
      status: 429,
      retryAfterSeconds: null,
      message: "Too many scans from this address. Please try again later.",
    })
  })

  it("reports a network failure as an unreachable API", async () => {
    mockFetch(async () => {
      throw new TypeError("Failed to fetch")
    })

    await expect(scanDomain("example.com")).rejects.toThrow(new ScanError(UNREACHABLE_ERROR))
  })

  it("gives up after the timeout", async () => {
    vi.useFakeTimers()
    try {
      vi.stubGlobal("fetch", hangingFetch())

      const result = scanDomain("example.com").catch((err: unknown) => err)
      await vi.advanceTimersByTimeAsync(SCAN_TIMEOUT_MS)

      const error = await result
      expect(error).toBeInstanceOf(ScanError)
      expect((error as ScanError).message).toBe(
        "The scan did not finish within 90 seconds. Please try again later.",
      )
    } finally {
      vi.useRealTimers()
    }
  })

  it("rethrows the AbortError when the caller cancels", async () => {
    vi.stubGlobal("fetch", hangingFetch())
    const controller = new AbortController()

    const result = scanDomain("example.com", controller.signal).catch((err: unknown) => err)
    controller.abort()

    const error = await result
    expect(error).not.toBeInstanceOf(ScanError)
    expect(error).toMatchObject({ name: "AbortError" })
  })

  it("reports a server error without problem details", async () => {
    mockFetch(async () => new Response("<h1>Bad gateway</h1>", { status: 502, headers: { "Content-Type": "text/html" } }))

    await expect(scanDomain("example.com")).rejects.toThrow(
      "The scanner API failed (HTTP 502). Please try again later.",
    )
  })

  it("rejects a 200 response that is not a report", async () => {
    mockFetch(async () => jsonResponse({ unexpected: true }))

    await expect(scanDomain("example.com")).rejects.toThrow(ScanError)
  })

  it("does not call anything when no API URL is configured", async () => {
    vi.stubEnv("NEXT_PUBLIC_API_URL", "")
    vi.stubEnv("NODE_ENV", "production")
    const fetchMock = mockFetch(async () => jsonResponse(sample))

    await expect(scanDomain("example.com")).rejects.toThrow("The scanner API is not available right now.")
    expect(fetchMock).not.toHaveBeenCalled()
  })
})

describe("parseRetryAfter", () => {
  it("reads delay-seconds and HTTP dates", () => {
    const now = Date.parse("2026-11-01T12:00:00Z")
    expect(parseRetryAfter("120", now)).toBe(120)
    expect(parseRetryAfter("Sun, 01 Nov 2026 12:01:30 GMT", now)).toBe(90)
    expect(parseRetryAfter("Sun, 01 Nov 2026 11:00:00 GMT", now)).toBe(0)
    expect(parseRetryAfter("soon", now)).toBeNull()
    expect(parseRetryAfter(null, now)).toBeNull()
  })
})

describe("formatWait", () => {
  it("uses seconds below two minutes and whole minutes above", () => {
    expect(formatWait(1)).toBe("1 second")
    expect(formatWait(45)).toBe("45 seconds")
    expect(formatWait(119)).toBe("119 seconds")
    expect(formatWait(301)).toBe("6 minutes")
  })
})

describe("loadSampleReport", () => {
  it("loads the sample report", async () => {
    mockFetch(async () => jsonResponse(sample))
    await expect(loadSampleReport()).resolves.toEqual(sample)
  })

  it("rejects with a ScanError when the file is missing", async () => {
    mockFetch(async () => new Response("not found", { status: 404 }))
    await expect(loadSampleReport()).rejects.toThrow("The sample report could not be loaded.")
  })
})
