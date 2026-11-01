import { render, screen } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { beforeEach, describe, expect, it, vi } from "vitest"
import { ScanWorkflow } from "./ScanWorkflow"
import { ApiProblemError, scanDomain } from "@/lib/api"
import { sampleReport as sample } from "@/test/sample-report"

vi.mock("@/lib/api", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/lib/api")>()),
  scanDomain: vi.fn(),
}))

const scanMock = vi.mocked(scanDomain)

beforeEach(() => {
  scanMock.mockReset()
})

async function submit(domain: string) {
  const user = userEvent.setup()
  render(<ScanWorkflow />)
  await user.type(screen.getByLabelText("Domain"), domain)
  await user.click(screen.getByRole("button", { name: "Check domain" }))
  return user
}

describe("ScanWorkflow", () => {
  it("shows the report as soon as the API responds", async () => {
    scanMock.mockResolvedValue({ ...sample, domain: "www.example.com" })

    await submit("https://WWW.Example.com/path")

    expect(scanMock).toHaveBeenCalledWith("www.example.com", expect.any(AbortSignal))
    expect(await screen.findByRole("heading", { level: 2, name: /www\.example\.com/ })).toBeInTheDocument()
  })

  it("announces the scan while it runs", async () => {
    scanMock.mockReturnValue(new Promise(() => {}))

    await submit("example.com")

    expect(screen.getByRole("status")).toHaveTextContent("Scanning example.com.")
  })

  it("shows the API's problem title and detail in an alert", async () => {
    scanMock.mockRejectedValue(
      new ApiProblemError({
        type: "https://webriskaudit.com/problems/domain-not-found",
        title: "Domain not found",
        status: 422,
        detail: "nope.example.org does not exist in DNS (NXDOMAIN).",
      }),
    )

    const user = await submit("nope.example.org")

    const alert = await screen.findByRole("alert")
    expect(alert).toHaveTextContent("Domain not found")
    expect(alert).toHaveTextContent("nope.example.org does not exist in DNS (NXDOMAIN).")

    await user.click(screen.getByRole("button", { name: "Try again" }))
    expect(screen.getByLabelText("Domain")).toHaveValue("nope.example.org")
  })

  it("validates the input before calling the API", async () => {
    await submit("ftp://example.com")

    expect(screen.getByRole("alert")).toHaveTextContent("Only http and https URLs are supported.")
    expect(screen.getByLabelText("Domain")).toHaveAttribute("aria-invalid", "true")
    expect(scanMock).not.toHaveBeenCalled()
  })
})
