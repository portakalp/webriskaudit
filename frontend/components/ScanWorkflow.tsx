"use client"

import { useState, useEffect, useCallback } from "react"
import { ScanForm } from "./ScanForm"
import { InteractiveScanDashboard } from "./InteractiveScanDashboard"
import { MiniReport } from "./MiniReport"
import { AlertCircle, X } from "lucide-react"
import type { ScanResult } from "@/lib/types"

export type WorkflowStep = "form" | "scanning" | "report"

export function ScanWorkflow({ onStepChange }: { onStepChange?: (step: WorkflowStep) => void }) {
  const [currentStep, setCurrentStep] = useState<WorkflowStep>("form")
  const [scanResults, setScanResults] = useState<ScanResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [animationComplete, setAnimationComplete] = useState(false)
  const [apiComplete, setApiComplete] = useState(false)

  // Notify parent of step changes
  useEffect(() => {
    if (onStepChange) {
      onStepChange(currentStep)
    }
  }, [currentStep, onStepChange])

  // When both animation and API are complete, show report
  useEffect(() => {
    if (animationComplete && apiComplete && scanResults) {
      setCurrentStep("report")
    }
  }, [animationComplete, apiComplete, scanResults])

  const handleFormSubmit = async (domain: string) => {
    // Clear any previous errors
    setError(null)

    // Reset completion states
    setAnimationComplete(false)
    setApiComplete(false)

    // Transition to scanning state
    setCurrentStep("scanning")

    try {
      // Get API URL from environment
      const apiUrl = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"

      // Call the /api/scan endpoint
      const response = await fetch(`${apiUrl}/api/scan`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ domain }),
      })

      if (!response.ok) {
        throw new Error(`Scan failed with status: ${response.status}`)
      }

      const data: ScanResult = await response.json()

      // Store scan results
      setScanResults(data)

      // Mark API as complete (report will show when animation also completes)
      setApiComplete(true)
    } catch (err) {
      console.error("Scan error:", err)

      // Set error message
      setError(
        err instanceof Error
          ? err.message
          : "Something went wrong. Please try again."
      )

      // Go back to form
      setCurrentStep("form")
    }
  }

  const handleAnimationComplete = useCallback(() => {
    setAnimationComplete(true)
  }, [])

  const handleReset = () => {
    setCurrentStep("form")
    setScanResults(null)
    setError(null)
  }

  const handleDismissError = () => {
    setError(null)
  }

  return (
    <div className="relative">
      {/* Error Banner */}
      {error && (
        <div className="mb-4 p-4 bg-red-50 border-2 border-red-200 rounded-xl flex items-start gap-3 animate-in fade-in slide-in-from-top duration-300">
          <AlertCircle className="w-5 h-5 text-red-600 flex-shrink-0 mt-0.5" />
          <div className="flex-1">
            <p className="text-sm font-medium text-red-900">Error</p>
            <p className="text-sm text-red-700 mt-1">{error}</p>
          </div>
          <button
            onClick={handleDismissError}
            className="text-red-400 hover:text-red-600 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>
      )}

      {/* Conditional Rendering Based on Step */}
      {currentStep === "form" && (
        <ScanForm onSubmit={handleFormSubmit} isLoading={false} />
      )}

      {currentStep === "scanning" && (
        <InteractiveScanDashboard onComplete={handleAnimationComplete} />
      )}

      {currentStep === "report" && scanResults && (
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
      )}
    </div>
  )
}
