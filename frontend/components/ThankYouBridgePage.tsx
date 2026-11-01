"use client"

import { useEffect } from "react"
import { Lock } from "lucide-react"

interface ThankYouBridgePageProps {
  email: string
  onReset: () => void
}

export function ThankYouBridgePage({ email, onReset }: ThankYouBridgePageProps) {
  // Load Calendly script on mount
  useEffect(() => {
    const script = document.createElement('script')
    script.src = 'https://assets.calendly.com/assets/external/widget.js'
    script.async = true
    document.body.appendChild(script)

    return () => {
      // Cleanup script on unmount
      const existingScript = document.querySelector('script[src="https://assets.calendly.com/assets/external/widget.js"]')
      if (existingScript) {
        document.body.removeChild(existingScript)
      }
    }
  }, [])

  return (
    <div className="animate-in fade-in slide-in-from-bottom duration-500">
      {/* Success Icon */}
      <div className="flex justify-center mb-6">
        <div className="w-20 h-20 bg-orange-100 rounded-full flex items-center justify-center">
          <Lock className="w-12 h-12 text-orange-600" />
        </div>
      </div>

      {/* Main Headline */}
      <h1 className="text-2xl md:text-3xl font-bold text-orange-500 text-center mb-2">
        Audit Complete.
      </h1>

      <p className="text-sm text-slate-600 text-center mb-6 max-w-lg mx-auto">
        Raw vulnerability data can be complex and misleading without context. We present your roadmap in a live session to ensure actionable results.
      </p>

      {/* SLA Notification */}
      <div className="bg-orange-50 border-2 border-orange-200 rounded-xl p-6 mb-8">
        <p className="text-sm text-orange-800 text-center leading-relaxed">
          Don't Guess, Know For Sure. Book your <strong className="font-bold text-orange-900">15-min Report Walkthrough</strong> to see exactly which risks threaten your business and how to remediate them.
        </p>
      </div>

      {/* Calendly Inline Embed */}
      <div className="calendly-container mb-8">
        <div
          className="calendly-inline-widget"
          data-url="https://calendly.com/webriskaudit/free-diagnosis?hide_event_type_details=1&hide_gdpr_banner=1&primary_color=ff7d00"
          style={{ minWidth: '320px', height: '700px' }}
        />
      </div>

      {/* Alternative: Scan Another Domain */}
      <div className="text-center">
        <button
          onClick={onReset}
          className="text-sm text-slate-600 hover:text-slate-900 transition-colors underline"
        >
          Scan Another Domain
        </button>
      </div>
    </div>
  )
}
