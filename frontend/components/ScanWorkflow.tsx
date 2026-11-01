"use client"

import { useState, useEffect, useCallback, useRef } from "react"
import { ScanForm } from "./ScanForm"
import { InteractiveScanDashboard } from "./InteractiveScanDashboard"
import { MiniReport } from "./MiniReport"
import { AlertCircle, FileText, RotateCcw } from "lucide-react"
import { ScanError, loadSampleReport, scanDomain } from "@/lib/api"
import type { ScanResult } from "@/lib/types"

export type WorkflowStep = "form" | "scanning" | "report" | "error"

const GENERIC_ERROR = "Something went wrong. Please try again later."

export function ScanWorkflow({ onStepChange }: { onStepChange?: (step: WorkflowStep) => void }) {
  const [step, setStep] = useState<WorkflowStep>("form")
  const [scanResults, setScanResults] = useState<ScanResult | null>(null)
  const [isSample, setIsSample] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [animationComplete, setAnimationComplete] = useState(false)
  const [apiComplete, setApiComplete] = useState(false)
  const scanControllerRef = useRef<AbortController | null>(null)

  // The report is shown once both the animation and the API call have finished
  const currentStep: WorkflowStep =
    step === "scanning" && animationComplete && apiComplete && scanResults ? "report" : step

  // Notify parent of step changes
  useEffect(() => {
    if (onStepChange) {
      onStepChange(currentStep)
    }
  }, [currentStep, onStepChange])

  // Cancel a running scan when the component unmounts
  useEffect(() => {
    return () => scanControllerRef.current?.abort()
  }, [])

  const handleFormSubmit = async (domain: string) => {
    scanControllerRef.current?.abort()
    const controller = new AbortController()
    scanControllerRef.current = controller

    // Reset state from any previous scan
    setError(null)
    setScanResults(null)
    setIsSample(false)
    setAnimationComplete(false)
    setApiComplete(false)

    // Transition to scanning state
    setStep("scanning")

    try {
      const data = await scanDomain(domain, controller.signal)

      // Report will show when the animation also completes
      setScanResults(data)
      setApiComplete(true)
    } catch (err) {
      // Cancelled by a reset or unmount
      if (controller.signal.aborted) return

      setError(err instanceof ScanError ? err.message : GENERIC_ERROR)
      setStep("error")
    }
  }

  const handleAnimationComplete = useCallback(() => {
    setAnimationComplete(true)
  }, [])

  const handleViewSample = async () => {
    scanControllerRef.current?.abort()
    setError(null)

    try {
      const sample = await loadSampleReport()
      setScanResults(sample)
      setIsSample(true)
      setStep("report")
    } catch (err) {
      setError(err instanceof ScanError ? err.message : "The sample report could not be loaded.")
      setStep("error")
    }
  }

  const handleReset = () => {
    scanControllerRef.current?.abort()
    setStep("form")
    setScanResults(null)
    setIsSample(false)
    setError(null)
  }

  return (
    <div className="relative">
      {/* Conditional Rendering Based on Step */}
      {currentStep === "form" && (
        <>
          <ScanForm onSubmit={handleFormSubmit} isLoading={false} />
          <p className="mt-3 text-center">
            <button
              type="button"
              onClick={handleViewSample}
              className="text-xs text-slate-500 hover:text-slate-900 underline transition-colors"
            >
              View a sample report
            </button>
          </p>
        </>
      )}

      {currentStep === "scanning" && (
        <InteractiveScanDashboard onComplete={handleAnimationComplete} />
      )}

      {currentStep === "error" && (
        <div className="mt-6 space-y-4 animate-in fade-in duration-300">
          <div className="p-4 bg-red-50 border-2 border-red-200 rounded-xl flex items-start gap-3" role="alert">
            <AlertCircle className="w-5 h-5 text-red-600 flex-shrink-0 mt-0.5" />
            <div className="flex-1">
              <p className="text-sm font-medium text-red-900">The scan could not be completed</p>
              <p className="text-sm text-red-700 mt-1">{error}</p>
            </div>
          </div>

          <div className="flex flex-col sm:flex-row gap-3">
            <button
              onClick={handleReset}
              className="flex-1 py-3 px-6 bg-white border-2 border-slate-200 text-slate-700 font-semibold text-sm rounded-xl hover:bg-slate-50 hover:border-slate-300 transition-colors flex items-center justify-center gap-2"
            >
              <RotateCcw className="w-4 h-4" />
              <span>Try Again</span>
            </button>
            <button
              onClick={handleViewSample}
              className="flex-1 py-3 px-6 bg-white border-2 border-slate-200 text-slate-700 font-semibold text-sm rounded-xl hover:bg-slate-50 hover:border-slate-300 transition-colors flex items-center justify-center gap-2"
            >
              <FileText className="w-4 h-4" />
              <span>View Sample Report</span>
            </button>
          </div>
        </div>
      )}

      {currentStep === "report" && scanResults && (
        <>
          {isSample && (
            <div className="mt-6 p-4 bg-amber-50 border-2 border-amber-200 rounded-xl text-sm text-amber-900" role="note">
              Sample report for webriskaudit.com, captured 1 November 2026. The live scanner API is being rebuilt.
            </div>
          )}

          <MiniReport
            score={scanResults.score}
            riskLevel={scanResults.risk_level}
            emailSecurity={scanResults.email_security}
            serverSecurity={scanResults.server_security}
            compliance={scanResults.compliance}

            spfStatus={scanResults.spf_status}
            dkimStatus={scanResults.dkim_status}
            dmarcStatus={scanResults.dmarc_status}
            blacklistStatus={scanResults.blacklist_status}
            wafStatus={scanResults.waf_status}
            sslStatus={scanResults.ssl_status}
            serverLeak={scanResults.server_leak}
            securityHeadersScore={scanResults.security_headers_score}
            complianceRisk={scanResults.compliance_risk}
            onReset={handleReset}
          />
        </>
      )}
    </div>
  )
}
