"use client"

import { useEffect, useRef, useState } from "react"
import { AlertCircle, FileText, RotateCcw } from "lucide-react"
import { ScanForm } from "./ScanForm"
import { InteractiveScanDashboard } from "./InteractiveScanDashboard"
import { ReportView } from "./report/ReportView"
import { ApiProblemError, GENERIC_ERROR, ScanError, loadSampleReport, scanDomain } from "@/lib/api"
import type { ScanReport } from "@/lib/types"

export type WorkflowStep = "form" | "scanning" | "report" | "error"

interface ErrorMessage {
  title: string
  message: string
}

const SECONDARY_BUTTON =
  "flex flex-1 items-center justify-center gap-2 rounded-xl border-2 border-slate-200 bg-white px-6 py-3 text-sm font-semibold text-slate-800 transition-colors hover:border-slate-300 hover:bg-slate-50"

export function ScanWorkflow({ onStepChange }: { onStepChange?: (step: WorkflowStep) => void }) {
  const [step, setStep] = useState<WorkflowStep>("form")
  const [domain, setDomain] = useState("")
  const [report, setReport] = useState<ScanReport | null>(null)
  const [isSample, setIsSample] = useState(false)
  const [error, setError] = useState<ErrorMessage | null>(null)
  const scanControllerRef = useRef<AbortController | null>(null)

  useEffect(() => {
    onStepChange?.(step)
  }, [step, onStepChange])

  // Cancel a running scan when the component unmounts
  useEffect(() => {
    return () => scanControllerRef.current?.abort()
  }, [])

  const handleFormSubmit = async (target: string) => {
    scanControllerRef.current?.abort()
    const controller = new AbortController()
    scanControllerRef.current = controller

    setDomain(target)
    setError(null)
    setReport(null)
    setIsSample(false)
    setStep("scanning")

    try {
      // The report replaces the animation as soon as the API responds
      const result = await scanDomain(target, controller.signal)
      if (controller.signal.aborted) return
      setReport(result)
      setStep("report")
    } catch (err) {
      // Cancelled by a reset or unmount
      if (controller.signal.aborted) return
      setError(describeError(err))
      setStep("error")
    }
  }

  const handleViewSample = async () => {
    scanControllerRef.current?.abort()
    setError(null)

    try {
      setReport(await loadSampleReport())
      setIsSample(true)
      setStep("report")
    } catch (err) {
      setError(describeError(err))
      setStep("error")
    }
  }

  const handleReset = () => {
    scanControllerRef.current?.abort()
    setDomain("")
    setReport(null)
    setIsSample(false)
    setError(null)
    setStep("form")
  }

  // Back to the form with the failed domain filled in
  const handleRetry = () => {
    setError(null)
    setStep("form")
  }

  return (
    <div className="relative">
      <p role="status" aria-live="polite" className="sr-only">
        {step === "scanning" ? `Scanning ${domain}. Most scans finish within a few seconds.` : ""}
      </p>

      {step === "form" && (
        <>
          <ScanForm onSubmit={handleFormSubmit} initialValue={domain} />
          <p className="mt-3 text-center">
            <button
              type="button"
              onClick={handleViewSample}
              className="rounded text-sm text-slate-700 underline underline-offset-2 transition-colors hover:text-slate-900"
            >
              View a sample report
            </button>
          </p>
        </>
      )}

      {step === "scanning" && <InteractiveScanDashboard domain={domain} />}

      {step === "error" && error && (
        <div className="mt-6 space-y-4 animate-in fade-in duration-300">
          <div role="alert" className="flex items-start gap-3 rounded-xl border-2 border-red-200 bg-red-50 p-4">
            <AlertCircle className="mt-0.5 h-5 w-5 shrink-0 text-red-700" aria-hidden="true" />
            <div className="flex-1">
              <p className="text-sm font-semibold text-red-900">{error.title}</p>
              <p className="mt-1 text-sm text-red-800">{error.message}</p>
            </div>
          </div>

          <div className="flex flex-col gap-3 sm:flex-row">
            <button type="button" onClick={handleRetry} className={SECONDARY_BUTTON}>
              <RotateCcw className="h-4 w-4" aria-hidden="true" />
              Try again
            </button>
            <button type="button" onClick={handleViewSample} className={SECONDARY_BUTTON}>
              <FileText className="h-4 w-4" aria-hidden="true" />
              View sample report
            </button>
          </div>
        </div>
      )}

      {step === "report" && report && (
        <div className="space-y-6">
          {isSample && (
            <div role="note" className="rounded-xl border-2 border-amber-200 bg-amber-50 p-4 text-sm text-amber-900">
              Example report with illustrative values. It is not the result of a real scan.
            </div>
          )}
          <ReportView key={`${report.domain}-${report.scanned_at}`} report={report} onReset={handleReset} />
        </div>
      )}
    </div>
  )
}

function describeError(err: unknown): ErrorMessage {
  if (err instanceof ApiProblemError) {
    return { title: err.title, message: err.message }
  }
  return {
    title: "The scan could not be completed",
    message: err instanceof ScanError ? err.message : GENERIC_ERROR,
  }
}
