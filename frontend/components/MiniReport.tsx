"use client"

import {
  Shield,
  Mail,
  CheckCircle,
  XCircle,
  AlertTriangle,
  RotateCcw,
  FileCheck
} from "lucide-react"
import { CategoryScoreCard } from "./CategoryScoreCard"
import type { CategoryScore, RiskLevel } from "@/lib/types"

interface MiniReportProps {
  score: number
  riskLevel: RiskLevel

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

  onReset: () => void
}

export function MiniReport({
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
  onReset
}: MiniReportProps) {
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

      {/* Findings - Full Width */}
      {(!wafStatus || !dmarcStatus || !sslStatus || securityHeadersScore < 4) && (
        <div className="space-y-2 p-4 bg-red-50 border-2 border-red-200 rounded-xl">
          <h4 className="text-sm font-semibold text-red-900 flex items-center gap-2">
            <AlertTriangle className="w-4 h-4" />
            Findings to Review
          </h4>
          <div className="space-y-1">
            {!wafStatus && <p className="text-xs text-red-700">No CDN or WAF detected</p>}
            {!dmarcStatus && <p className="text-xs text-red-700">No DMARC record found</p>}
            {!sslStatus && <p className="text-xs text-red-700">TLS certificate invalid or expiring within 30 days</p>}
            {securityHeadersScore < 4 && (
              <p className="text-xs text-red-700">{5 - securityHeadersScore} of 5 security headers missing</p>
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
                <span className="text-sm text-slate-700">DKIM Record (Common Selectors)</span>
              </div>

              {/* DMARC Policy */}
              <div className="flex items-center gap-3">
                {dmarcStatus ? (
                  <CheckCircle className="w-5 h-5 text-emerald-600 flex-shrink-0" />
                ) : (
                  <XCircle className="w-5 h-5 text-red-600 flex-shrink-0" />
                )}
                <span className="text-sm text-slate-700">DMARC Record</span>
              </div>

              {/* Blacklist Status */}
              <div className="flex items-center gap-3">
                {blacklistStatus ? (
                  <CheckCircle className="w-5 h-5 text-emerald-600 flex-shrink-0" />
                ) : (
                  <AlertTriangle className="w-5 h-5 text-red-600 flex-shrink-0" />
                )}
                <span className="text-sm text-slate-700">Not on DNS Blocklists</span>
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
                <span className="text-sm text-slate-700">CDN / WAF Detected</span>
              </div>

              {/* SSL Encryption */}
              <div className="flex items-center gap-3">
                {sslStatus ? (
                  <CheckCircle className="w-5 h-5 text-emerald-600 flex-shrink-0" />
                ) : (
                  <XCircle className="w-5 h-5 text-red-600 flex-shrink-0" />
                )}
                <span className="text-sm text-slate-700">Valid TLS Certificate</span>
              </div>

              {/* Server Identity */}
              <div className="flex items-center gap-3">
                {!serverLeak ? (
                  <CheckCircle className="w-5 h-5 text-emerald-600 flex-shrink-0" />
                ) : (
                  <AlertTriangle className="w-5 h-5 text-amber-600 flex-shrink-0" />
                )}
                <span className="text-sm text-slate-700">Server Header Hides Software</span>
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

        {/* COLUMN 3: Privacy */}
        <div className="space-y-4">
          <CategoryScoreCard
            title="Privacy"
            icon={FileCheck}
            score={compliance.score}
            max={compliance.max}
            percentage={compliance.percentage}
            riskLevel={compliance.risk_level}
          />

          <div className="border-2 border-purple-200 rounded-xl p-5 bg-white">
            <div className="flex items-center gap-2 mb-4">
              <h3 className="text-lg font-bold text-slate-900">Privacy Checks</h3>
            </div>

            <div className="space-y-2.5">
              {/* Privacy Policy */}
              <div className="flex items-center gap-3">
                {!complianceRisk ? (
                  <CheckCircle className="w-5 h-5 text-emerald-600 flex-shrink-0" />
                ) : (
                  <XCircle className="w-5 h-5 text-red-600 flex-shrink-0" />
                )}
                <span className="text-sm text-slate-700">Privacy Policy Page</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      <p className="text-xs text-slate-500 text-center text-pretty">
        These results come from automated, heuristic checks and can be incomplete or wrong. They are not a
        substitute for a professional security assessment.
      </p>

      <div>
        <button
          onClick={onReset}
          className="w-full py-3 px-6 bg-white border-2 border-slate-200 text-slate-700 font-semibold text-sm rounded-xl hover:bg-slate-50 hover:border-slate-300 transition-colors flex items-center justify-center gap-2"
        >
          <RotateCcw className="w-4 h-4" />
          <span>Scan Another Domain</span>
        </button>
      </div>
    </div>
  )
}
