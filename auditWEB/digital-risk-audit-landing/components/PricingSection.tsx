"use client"

import { useEffect } from "react"
import { Check, Shield } from "lucide-react"

export function PricingSection() {
  useEffect(() => {
    // Load Calendly CSS
    const head = document.querySelector("head")
    const link = document.createElement("link")
    link.href = "https://assets.calendly.com/assets/external/widget.css"
    link.rel = "stylesheet"
    head?.appendChild(link)

    // Load Calendly JS
    const script = document.createElement("script")
    script.src = "https://assets.calendly.com/assets/external/widget.js"
    script.async = true
    document.body.appendChild(script)

    return () => {
      // Cleanup might be tricky with external scripts, but we can try to remove them if needed.
      // Usually keeping them is fine as they are idempotent or check for existence.
      // For now, we'll leave them as they don't harm navigation.
      head?.removeChild(link)
      document.body.removeChild(script)
    }
  }, [])

  const openCalendly = (e: React.MouseEvent) => {
    e.preventDefault()
    if ((window as any).Calendly) {
      (window as any).Calendly.initPopupWidget({
        url: 'https://calendly.com/webriskaudit/free-diagnosis?hide_event_type_details=1&hide_gdpr_banner=1'
      })
    }
  }

  return (
    <section className="py-16 px-4 md:px-8 bg-[#F8FAFC] relative z-10" id="pricing">
      <div className="max-w-7xl mx-auto">
        <div className="text-center mb-12">
          <h2 className="text-3xl md:text-4xl font-bold text-slate-900 mb-4">
            Clear Pricing for Clear Risks
          </h2>
          <p className="text-lg text-slate-600 max-w-2xl mx-auto">
            Expert-led security audits. No hidden fees. Choose the protection level your business needs.
          </p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 mb-20 items-start">
          {/* Card 1: Cyber Shield */}
          <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-8 flex flex-col relative hover:shadow-md transition-shadow h-full">
            <div className="mb-4">
              <h3 className="text-xl font-bold text-slate-900">Cyber Shield</h3>
              <p className="text-sm text-slate-500 mt-1">Agencies & SMBs</p>
            </div>
            <div className="mb-6">
              <span className="text-3xl font-bold text-slate-900">$2,500</span>
              <span className="text-slate-500 text-sm ml-1">/ one-time</span>
            </div>
            <p className="text-slate-600 mb-6 text-sm">
              Get a clear risk picture and a prioritized backlog.
            </p>
            <div className="space-y-3 mb-8 flex-1">
              <FeatureItem text="Phase 0: Preflight Snapshot (24h)" />
              <FeatureItem text="Phase 1: Full Audit (7-10 bus. days)" />
              <FeatureItem text="Evidence-based Audit Report (PDF)" />
              <FeatureItem text="Attack Surface & Deliverability Checks" />
              <FeatureItem text="Prioritized Remediation Backlog" />
              <p className="text-xs text-slate-400 italic mt-2">
                *Phase 0: No access, no fixes, no active scanning.
              </p>
            </div>
            <button
              onClick={openCalendly}
              className="w-full py-2.5 px-4 rounded-lg border border-slate-300 text-slate-700 font-medium hover:bg-slate-50 hover:text-slate-900 transition-all hover:shadow-md hover:-translate-y-0.5 active:translate-y-0 active:shadow-sm"
            >
              Select Cyber Shield
            </button>
          </div>

          {/* Card 2: Full Armor */}
          <div className="bg-white rounded-xl shadow-lg border-2 border-orange-500 p-8 flex flex-col relative lg:-translate-y-4 z-10 h-full">
            <div className="absolute top-0 left-1/2 -translate-x-1/2 -translate-y-1/2 bg-orange-500 text-white text-xs font-bold px-3 py-1 rounded-full uppercase tracking-wide shadow-sm">
              Most Popular
            </div>
            <div className="mb-4">
              <h3 className="text-xl font-bold text-slate-900">Full Armor</h3>
              <p className="text-sm text-slate-500 mt-1">Teams needing governance</p>
            </div>
            <div className="mb-6">
              <span className="text-3xl font-bold text-slate-900">$3,900</span>
              <span className="text-slate-500 text-sm ml-1">/ one-time</span>
            </div>
            <p className="text-slate-600 mb-6 text-sm">
              Includes everything in Cyber Shield plus governance and phishing readiness.
            </p>
            <div className="space-y-3 mb-8 flex-1">
              <div className="flex items-center gap-2 text-sm font-medium text-slate-900">
                <div className="flex-shrink-0 w-5 h-5 rounded-full bg-orange-100 flex items-center justify-center">
                  <Check className="w-3.5 h-3.5 text-orange-600" />
                </div>
                Everything in Cyber Shield (10-15 days)
              </div>
              <FeatureItem text="Web Supply Chain Report (No-source)" />
              <FeatureItem text="Governance Kit + Awareness Pack" />
              <FeatureItem text="Phishing Report + 60-min Presentation" />
              <div className="flex items-center gap-2 text-sm text-slate-900 font-semibold bg-orange-50 p-3 rounded-lg -mx-2 mt-2">
                 <Shield className="w-4 h-4 text-orange-500" />
                 BONUS: 1 Month Digital Bodyguard
              </div>
            </div>
            <button
              onClick={openCalendly}
              className="w-full py-2.5 px-4 rounded-lg bg-orange-500 text-white font-medium hover:bg-orange-600 transition-all shadow-sm hover:shadow-lg hover:-translate-y-0.5 active:translate-y-0 active:shadow-sm"
            >
              Get Full Armor
            </button>
          </div>

          {/* Card 3: Digital Bodyguard */}
          <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-8 flex flex-col relative hover:shadow-md transition-shadow h-full">
            <div className="mb-4">
              <h3 className="text-xl font-bold text-slate-900">Digital Bodyguard</h3>
              <p className="text-sm text-slate-500 mt-1">Ongoing Protection</p>
            </div>
            <div className="mb-6">
              <span className="text-3xl font-bold text-slate-900">$500</span>
              <span className="text-slate-500 text-sm ml-1">/ month</span>
            </div>
            <p className="text-slate-600 mb-6 text-sm">
              Keep risk from creeping back after the audit.
            </p>
            <div className="space-y-3 mb-8 flex-1">
              <FeatureItem text="Target Slot: 1 domain OR 1 endpoint" />
              <FeatureItem text="Monthly Security Health Report" />
              <FeatureItem text="Triage Notes for Critical Findings" />
              <FeatureItem text="Vendor Change Tracking" />
              <p className="text-xs text-slate-400 italic mt-2">
                *Monitoring continuous; triage/response during business hours.
              </p>
            </div>
            <button
              onClick={openCalendly}
              className="w-full text-center py-2.5 px-4 rounded-lg border border-slate-300 text-slate-700 font-medium hover:bg-slate-50 hover:text-slate-900 transition-all hover:shadow-md hover:-translate-y-0.5 active:translate-y-0 active:shadow-sm"
            >
              Book a Call
            </button>
          </div>
        </div>

        {/* Notes & Disclaimers */}
        <div className="mb-16 max-w-4xl mx-auto bg-slate-50 p-6 rounded-xl text-sm text-slate-600 space-y-2 border border-slate-200">
             <p className="font-semibold text-slate-800 mb-1">Important Scope & Authorization Notes:</p>
             <ul className="list-disc list-inside space-y-1">
                 <li><strong>Implementation/fixes are NOT included.</strong> We provide the assessment, evidence, and prioritized backlog; your team implements the fixes.</li>
                 <li><strong>Active Scanning:</strong> Only performed with written authorization and an agreed scope/time window.</li>
                 <li><strong>Phase 0:</strong> Includes no access, no fixes, and no active scanning.</li>
                 <li><strong>DAST Scanning:</strong> Includes 1 domain/subdomain. Each additional domain/subdomain is +$200.</li>
             </ul>
        </div>

        {/* Process Timeline */}
        <div className="mt-16 pt-16 border-t border-slate-200">
            <h3 className="text-2xl font-bold text-slate-900 text-center mb-16">How It Works</h3>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-8 relative max-w-4xl mx-auto">
                {/* Connecting Line (Desktop) */}
                <div className="hidden md:block absolute top-[26px] left-[16%] right-[16%] h-0.5 bg-slate-200 -z-10"></div>
                
                {/* Step 1 */}
                <div className="flex flex-col items-center text-center">
                    <div className="w-14 h-14 bg-white border-2 border-slate-200 rounded-full flex items-center justify-center mb-6 z-10 text-slate-900 font-bold shadow-sm text-lg">
                        0
                    </div>
                    <h4 className="text-lg font-bold text-slate-900 mb-2">Phase 0 (Preflight)</h4>
                    <p className="text-slate-600 text-sm max-w-[200px]">24-hour snapshot, no access needed.</p>
                </div>

                {/* Step 2 */}
                <div className="flex flex-col items-center text-center">
                    <div className="w-14 h-14 bg-orange-500 border-2 border-orange-500 rounded-full flex items-center justify-center mb-6 z-10 text-white font-bold shadow-md text-lg">
                        1
                    </div>
                    <h4 className="text-lg font-bold text-slate-900 mb-2">Phase 1 (Audit)</h4>
                    <p className="text-slate-600 text-sm max-w-[200px]">Deep dive technical testing & roadmap.</p>
                </div>

                 {/* Step 3 */}
                 <div className="flex flex-col items-center text-center">
                    <div className="w-14 h-14 bg-white border-2 border-slate-200 rounded-full flex items-center justify-center mb-6 z-10 text-slate-900 font-bold shadow-sm text-lg">
                        2
                    </div>
                    <h4 className="text-lg font-bold text-slate-900 mb-2">Phase 2 (Governance)</h4>
                    <p className="text-slate-600 text-sm max-w-[200px]">Supply chain & human layer defense.</p>
                </div>
            </div>
        </div>
      </div>
    </section>
  )
}

function FeatureItem({ text }: { text: string }) {
  return (
    <div className="flex items-start gap-3">
      <Check className="w-5 h-5 text-blue-500 shrink-0 mt-0.5" />
      <span className="text-sm text-slate-600 text-left">{text}</span>
    </div>
  )
}
