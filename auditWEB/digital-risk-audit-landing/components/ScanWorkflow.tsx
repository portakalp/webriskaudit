"use client"

import { useState, useEffect, useCallback } from "react"
import { ScanForm } from "./ScanForm"
import { InteractiveScanDashboard } from "./InteractiveScanDashboard"
import { MiniReport } from "./MiniReport"
import { ThankYouBridgePage } from "./ThankYouBridgePage"
import { AlertCircle, X } from "lucide-react"
import { checkRateLimit, getResetTime } from "@/lib/rateLimiter"

export type WorkflowStep = "form" | "scanning" | "report" | "success"

interface CategoryScore {
  score: number
  max: number
  percentage: number
  risk_level: "SECURE" | "MODERATE" | "CRITICAL"
}

interface ScanResults {
  lead_id: number
  scan_id: number
  domain: string
  score: number
  risk_level: "SECURE" | "MODERATE" | "CRITICAL"

  // Email & Reputation
  spf_status: boolean
  dkim_status: boolean
  dmarc_status: boolean
  blacklist_status: boolean

  // Server Security
  waf_status: boolean
  ssl_status: boolean
  server_leak: boolean
  security_headers_score: number

  // Compliance
  compliance_risk: boolean
  cookie_consent_detected: boolean
  data_leak_safe: boolean

  // NEW - Category scores
  email_security: CategoryScore
  server_security: CategoryScore
  compliance: CategoryScore
}

export function ScanWorkflow({ onStepChange }: { onStepChange?: (step: WorkflowStep) => void }) {
  const [currentStep, setCurrentStep] = useState<WorkflowStep>("form")
  const [formData, setFormData] = useState({ email: "", domain: "" })
  const [scanResults, setScanResults] = useState<ScanResults | null>(null)
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

  const handleFormSubmit = async (email: string, domain: string) => {
    // Check rate limit (3 requests per minute per email)
    if (!checkRateLimit(email, 3, 60000)) {
      const resetTime = getResetTime(email)
      const secondsRemaining = Math.ceil(resetTime / 1000)
      setError(
        `Too many requests. Please wait ${secondsRemaining} seconds before trying again.`
      )
      return
    }

    // Store form data
    setFormData({ email, domain })

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
        body: JSON.stringify({
          email,
          domain,
        }),
      })

      if (!response.ok) {
        throw new Error(`Scan failed with status: ${response.status}`)
      }

      const data = await response.json()

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

  const handleRequestFullReport = async (leadId: number) => {
    setError(null)

    try {
      const apiUrl = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"

      // Call the /api/request-full-report endpoint
      const response = await fetch(`${apiUrl}/api/request-full-report`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          lead_id: leadId,
        }),
      })

      if (!response.ok) {
        throw new Error(`Request failed with status: ${response.status}`)
      }

      // Transition to success state
      setCurrentStep("success")
    } catch (err) {
      console.error("Full report request error:", err)

      // Set error message
      setError(
        "Failed to request full report. Please try again or contact support."
      )
    }
  }

  const handleReset = () => {
    setCurrentStep("form")
    setFormData({ email: "", domain: "" })
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
          leadId={scanResults.lead_id}
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
          cookieConsentDetected={scanResults.cookie_consent_detected}
          dataLeakSafe={scanResults.data_leak_safe}
          onRequestFullReport={handleRequestFullReport}
        />
      )}

      {currentStep === "success" && (
        <ThankYouBridgePage email={formData.email} onReset={handleReset} />
      )}
    </div>
  )
}
