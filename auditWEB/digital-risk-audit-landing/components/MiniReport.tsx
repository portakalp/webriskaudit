"use client"

import type React from "react"
import { useState } from "react"
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  Mail,
  FileText,
  CheckCircle,
  XCircle,
  AlertTriangle,
  ArrowRight,
  Loader2,
  FileCheck
} from "lucide-react"
import { CategoryScoreCard } from "./CategoryScoreCard"

interface CategoryScore {
  score: number
  max: number
  percentage: number
  risk_level: "SECURE" | "MODERATE" | "CRITICAL"
}

interface MiniReportProps {
  leadId: number
  score: number
  riskLevel: "SECURE" | "MODERATE" | "CRITICAL"

  // NEW - Category scores
  emailSecurity: CategoryScore
  serverSecurity: CategoryScore
  compliance: CategoryScore

  // Email & Reputation
  spfStatus: boolean
  dkimStatus: boolean
  dmarcStatus: boolean
  blacklistStatus: boolean

  // Server Security
  wafStatus: boolean
  sslStatus: boolean
  serverLeak: boolean
  securityHeadersScore: number

  // Compliance
  complianceRisk: boolean
  cookieConsentDetected: boolean
  dataLeakSafe: boolean

  onRequestFullReport: (leadId: number) => void
}

export function MiniReport({
  leadId,
  score,
  riskLevel,
  emailSecurity,
  serverSecurity,
  compliance,
  spfStatus,
  dkimStatus,
  dmarcStatus,
  blacklistStatus,
  wafStatus,
  sslStatus,
  serverLeak,
  securityHeadersScore,
  complianceRisk,
  cookieConsentDetected,
  dataLeakSafe,
  onRequestFullReport
}: MiniReportProps) {
  const [isRequesting, setIsRequesting] = useState(false)

  const handleRequestReport = async () => {
    setIsRequesting(true)
    try {
      await onRequestFullReport(leadId)
    } finally {
      setIsRequesting(false)
    }
  }

  // Determine score color and badge
  const getScoreColor = () => {
    if (score >= 80) return { bg: "bg-emerald-50", text: "text-emerald-700", border: "border-emerald-200", progress: "bg-emerald-500" }
    if (score >= 50) return { bg: "bg-yellow-50", text: "text-yellow-700", border: "border-yellow-200", progress: "bg-yellow-500" }
    return { bg: "bg-red-50", text: "text-red-700", border: "border-red-200", progress: "bg-red-500" }
  }

  const scoreColors = getScoreColor()

  return (
    <div className="mt-6 space-y-6 animate-in fade-in duration-500">
      {/* Section 1: Security Score Gauge */}
      <div className={`p-6 rounded-2xl border-2 ${scoreColors.border} ${scoreColors.bg}`}>
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-bold text-slate-900">Security Score</h3>
          <span className={`px-3 py-1 rounded-full text-xs font-semibold ${scoreColors.text} ${scoreColors.bg} border ${scoreColors.border}`}>
            {riskLevel}
          </span>
        </div>

        {/* Score Display */}
        <div className="text-center mb-4">
          <div className="text-5xl font-bold text-slate-900 mb-1">
            {score}
            <span className="text-2xl text-slate-500">/100</span>
          </div>
        </div>

        {/* Progress Bar */}
        <div className="relative">
          <div className="h-3 w-full bg-slate-200 rounded-full overflow-hidden">
            <div
              className={`h-full ${scoreColors.progress} transition-all duration-1000 ease-out rounded-full`}
              style={{ width: `${score}%` }}
            />
          </div>
        </div>
      </div>

      {/* Critical Findings - Full Width */}
      {(!wafStatus || !dmarcStatus || !sslStatus || securityHeadersScore < 4) && (
        <div className="space-y-2 p-4 bg-red-50 border-2 border-red-200 rounded-xl">
          <h4 className="text-sm font-semibold text-red-900 flex items-center gap-2">
            <AlertTriangle className="w-4 h-4" />
            Critical Findings
          </h4>
          <div className="space-y-1">
            {!wafStatus && <p className="text-xs text-red-700">⚠ WAF Not Detected</p>}
            {!dmarcStatus && <p className="text-xs text-red-700">⚠ DMARC Not Configured</p>}
            {!sslStatus && <p className="text-xs text-red-700">⚠ SSL Certificate Issue</p>}
            {securityHeadersScore < 4 && (
              <p className="text-xs text-red-700">⚠ {5 - securityHeadersScore} Security Headers Missing</p>
            )}
          </div>
        </div>
      )}

      {/* THREE-COLUMN LAYOUT */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* COLUMN 1: Email Security */}
        <div className="space-y-4">
          <CategoryScoreCard
            title="Email Security"
            icon={Mail}
            score={emailSecurity.score}
            max={emailSecurity.max}
            percentage={emailSecurity.percentage}
            riskLevel={emailSecurity.risk_level}
          />

          <div className="border-2 border-emerald-200 rounded-xl p-5 bg-white">
            <div className="flex items-center gap-2 mb-4">
              <h3 className="text-lg font-bold text-slate-900">Spam & Deliverability</h3>
            </div>

            <div className="space-y-2.5">
              {/* SPF Record */}
              <div className="flex items-center gap-3">
                {spfStatus ? (
                  <CheckCircle className="w-5 h-5 text-emerald-600 flex-shrink-0" />
                ) : (
                  <XCircle className="w-5 h-5 text-red-600 flex-shrink-0" />
                )}
                <span className="text-sm text-slate-700">SPF Record</span>
              </div>

              {/* DKIM Signature */}
              <div className="flex items-center gap-3">
                {dkimStatus ? (
                  <CheckCircle className="w-5 h-5 text-emerald-600 flex-shrink-0" />
                ) : (
                  <XCircle className="w-5 h-5 text-red-600 flex-shrink-0" />
                )}
                <span className="text-sm text-slate-700">DKIM Signature</span>
              </div>

              {/* DMARC Policy */}
              <div className="flex items-center gap-3">
                {dmarcStatus ? (
                  <CheckCircle className="w-5 h-5 text-emerald-600 flex-shrink-0" />
                ) : (
                  <XCircle className="w-5 h-5 text-red-600 flex-shrink-0" />
                )}
                <span className="text-sm text-slate-700">DMARC Policy (Anti-Spoofing)</span>
              </div>

              {/* Blacklist Status */}
              <div className="flex items-center gap-3">
                {blacklistStatus ? (
                  <CheckCircle className="w-5 h-5 text-emerald-600 flex-shrink-0" />
                ) : (
                  <AlertTriangle className="w-5 h-5 text-red-600 flex-shrink-0" />
                )}
                <span className="text-sm text-slate-700">Domain Blacklist Status</span>
              </div>
            </div>
          </div>
        </div>

        {/* COLUMN 2: Server Security */}
        <div className="space-y-4">
          <CategoryScoreCard
            title="Server Security"
            icon={Shield}
            score={serverSecurity.score}
            max={serverSecurity.max}
            percentage={serverSecurity.percentage}
            riskLevel={serverSecurity.risk_level}
          />

          <div className="border-2 border-blue-200 rounded-xl p-5 bg-white">
            <div className="flex items-center gap-2 mb-4">
              <h3 className="text-lg font-bold text-slate-900">Perimeter Security</h3>
            </div>

            <div className="space-y-2.5">
              {/* Active Firewall */}
              <div className="flex items-center gap-3">
                {wafStatus ? (
                  <CheckCircle className="w-5 h-5 text-emerald-600 flex-shrink-0" />
                ) : (
                  <XCircle className="w-5 h-5 text-red-600 flex-shrink-0" />
                )}
                <span className="text-sm text-slate-700">Active Firewall (WAF)</span>
              </div>

              {/* SSL Encryption */}
              <div className="flex items-center gap-3">
                {sslStatus ? (
                  <CheckCircle className="w-5 h-5 text-emerald-600 flex-shrink-0" />
                ) : (
                  <XCircle className="w-5 h-5 text-red-600 flex-shrink-0" />
                )}
                <span className="text-sm text-slate-700">SSL Encryption Strength</span>
              </div>

              {/* Server Identity */}
              <div className="flex items-center gap-3">
                {!serverLeak ? (
                  <CheckCircle className="w-5 h-5 text-emerald-600 flex-shrink-0" />
                ) : (
                  <AlertTriangle className="w-5 h-5 text-amber-600 flex-shrink-0" />
                )}
                <span className="text-sm text-slate-700">Server Identity Masking</span>
              </div>

              {/* Security Headers */}
              <div className="flex items-center gap-3">
                {securityHeadersScore >= 4 ? (
                  <CheckCircle className="w-5 h-5 text-emerald-600 flex-shrink-0" />
                ) : securityHeadersScore >= 2 ? (
                  <AlertTriangle className="w-5 h-5 text-amber-600 flex-shrink-0" />
                ) : (
                  <XCircle className="w-5 h-5 text-red-600 flex-shrink-0" />
                )}
                <span className="text-sm text-slate-700">
                  Security Headers ({securityHeadersScore}/5 Present)
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* COLUMN 3: Privacy Tech */}
        <div className="space-y-4">
          <CategoryScoreCard
            title="Privacy Tech"
            icon={FileCheck}
            score={compliance.score}
            max={compliance.max}
            percentage={compliance.percentage}
            riskLevel={compliance.risk_level}
          />

          <div className="border-2 border-purple-200 rounded-xl p-5 bg-white">
            <div className="flex items-center gap-2 mb-4">
              <h3 className="text-lg font-bold text-slate-900">Technical Privacy Checks</h3>
            </div>

            <div className="space-y-2.5">
              {/* Cookie Consent - NOW DYNAMIC */}
              <div className="flex items-center gap-3">
                {cookieConsentDetected ? (
                  <CheckCircle className="w-5 h-5 text-emerald-600 flex-shrink-0" />
                ) : (
                  <XCircle className="w-5 h-5 text-red-600 flex-shrink-0" />
                )}
                <span className="text-sm text-slate-700">Cookie Consent Logic</span>
              </div>

              {/* Privacy Policy */}
              <div className="flex items-center gap-3">
                {!complianceRisk ? (
                  <CheckCircle className="w-5 h-5 text-emerald-600 flex-shrink-0" />
                ) : (
                  <XCircle className="w-5 h-5 text-red-600 flex-shrink-0" />
                )}
                <span className="text-sm text-slate-700">Consent Banner Detection</span>
              </div>

              {/* Data Leak Check - NOW DYNAMIC */}
              <div className="flex items-center gap-3">
                {dataLeakSafe ? (
                  <CheckCircle className="w-5 h-5 text-emerald-600 flex-shrink-0" />
                ) : (
                  <AlertTriangle className="w-5 h-5 text-red-600 flex-shrink-0" />
                )}
                <span className="text-sm text-slate-700">Data Leak Check</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Section 3: CTA Button */}
      <div className="pt-4">
        <button
          onClick={handleRequestReport}
          disabled={isRequesting}
          className="relative w-full py-4 px-6 bg-gradient-to-r from-orange-500 to-amber-500 text-white font-bold text-sm rounded-xl shadow-xl shadow-orange-500/30 hover:shadow-2xl hover:shadow-orange-500/40 hover:from-orange-600 hover:to-amber-600 active:scale-[0.98] transition-all duration-300 disabled:opacity-70 disabled:cursor-not-allowed flex items-center justify-center gap-2 group"
        >
          {isRequesting ? (
            <>
              <Loader2 className="w-5 h-5 animate-spin" />
              <span>Sending Request...</span>
            </>
          ) : (
            <>
              <span>Get Remediation Plan</span>
              <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
            </>
          )}
        </button>

        <p className="text-xs text-slate-500 text-center mt-3">
          Our security experts will provide a detailed analysis and recommendations
        </p>
      </div>
    </div>
  )
}
