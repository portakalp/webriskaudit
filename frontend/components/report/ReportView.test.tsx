import { render, screen, within } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { describe, expect, it, vi } from "vitest"
import { ReportView } from "./ReportView"
import type { ScanReport } from "@/lib/types"
import { sampleReport as sample } from "@/test/sample-report"

function renderReport(report: ScanReport = sample) {
  const onReset = vi.fn()
  render(<ReportView report={report} onReset={onReset} />)
  return { onReset, user: userEvent.setup() }
}

/** The details panel that a check's disclosure button controls. */
function panelOf(button: HTMLElement): HTMLElement {
  const panel = document.getElementById(button.getAttribute("aria-controls") ?? "")
  if (!panel) throw new Error("disclosure has no panel")
  return panel
}

describe("ReportView", () => {
  it("shows the domain, score, grade and coverage", () => {
    renderReport()

    const heading = screen.getByRole("heading", { level: 2 })
    expect(heading).toHaveTextContent("example.com")
    expect(heading).toHaveFocus()
    expect(screen.getByText("Grade").nextSibling).toHaveTextContent("C")
    expect(screen.getByText("65")).toBeInTheDocument()
    expect(screen.getByText("11 of 12 scored checks completed, 1 inconclusive")).toBeInTheDocument()
  })

  it("says when there is not enough data for a score", () => {
    renderReport({ ...sample, score: null, grade: null })

    expect(screen.getByText("Not enough data for a score")).toBeInTheDocument()
    expect(screen.queryByText("Grade")).not.toBeInTheDocument()
  })

  it("groups the checks by category in API order", () => {
    renderReport()

    const groupHeadings = screen
      .getAllByRole("heading", { level: 3 })
      .map((heading) => heading.textContent)
      .filter((text) => text !== "Categories")
    expect(groupHeadings).toEqual([
      "Email authentication",
      "HTTPS and TLS",
      "HTTP security headers",
      "Informational",
    ])
    const email = screen.getByRole("region", { name: "Email authentication" })
    const checks = within(email).getAllByRole("heading", { level: 4 })
    expect(checks).toHaveLength(3)
    expect(checks[0]).toHaveAccessibleName("Pass SPF record")
    expect(checks[1]).toHaveAccessibleName("Warning DMARC policy")
    expect(checks[2]).toHaveAccessibleName("Inconclusive DKIM key")
  })

  it("announces every status as text, not only as colour", () => {
    renderReport()

    for (const name of [
      "Pass SPF record",
      "Warning DMARC policy",
      "Inconclusive DKIM key",
      "Fail Content Security Policy",
      "Info CDN / edge network",
    ]) {
      expect(screen.getByRole("button", { name })).toBeInTheDocument()
    }
    const counts = screen.getByRole("list", { name: "Results by status" })
    expect(within(counts).getAllByRole("listitem").map((item) => item.textContent)).toEqual([
      "Pass 5",
      "Warning 4",
      "Fail 2",
      "Inconclusive 1",
      "Info 4",
    ])
  })

  it("reveals evidence, remediation and references in a disclosure", async () => {
    const { user } = renderReport()
    const button = screen.getByRole("button", { name: "Fail Server version disclosure" })
    const panel = panelOf(button)

    expect(button).toHaveAttribute("aria-expanded", "false")
    expect(panel).not.toBeVisible()

    await user.click(button)

    expect(button).toHaveAttribute("aria-expanded", "true")
    expect(panel).toBeVisible()
    expect(within(panel).getByText("Server")).toBeVisible()
    expect(within(panel).getByText("nginx/1.24.0")).toBeVisible()
    expect(within(panel).getByText(/server_tokens off/)).toBeVisible()
    expect(within(panel).getByRole("link", { name: /MDN: Server/ })).toHaveAttribute(
      "href",
      "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Server",
    )

    await user.click(button)
    expect(panel).not.toBeVisible()
  })

  it("opens and closes every disclosure at once", async () => {
    const { user } = renderReport()

    await user.click(screen.getByRole("button", { name: "Show all details" }))
    for (const button of screen.getAllByRole("button", { expanded: true })) {
      expect(panelOf(button)).toBeVisible()
    }
    expect(screen.queryAllByRole("button", { expanded: false })).toHaveLength(0)

    await user.click(screen.getByRole("button", { name: "Hide all details" }))
    expect(screen.queryAllByRole("button", { expanded: true })).toHaveLength(0)
  })

  it("shows when and how the report was made", () => {
    renderReport()

    expect(screen.getByText("Scanner").nextSibling).toHaveTextContent(sample.scanner_version)
    expect(screen.getByText("Methodology").nextSibling).toHaveTextContent(sample.methodology_version)
    expect(screen.getByText("Duration").nextSibling).toHaveTextContent("512 ms")
    expect(document.querySelector("time")).toHaveAttribute("dateTime", sample.scanned_at)
  })

  it("starts over from the reset button", async () => {
    const { onReset, user } = renderReport()

    await user.click(screen.getByRole("button", { name: "Scan another domain" }))

    expect(onReset).toHaveBeenCalledOnce()
  })
})
