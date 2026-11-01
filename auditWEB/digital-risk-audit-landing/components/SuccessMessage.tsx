"use client"

import { useEffect } from "react"
import { CheckCircle, Mail, ArrowRight } from "lucide-react"

interface SuccessMessageProps {
  email: string
  onReset: () => void
}

export function SuccessMessage({ email, onReset }: SuccessMessageProps) {
  useEffect(() => {
    // Optional: Auto-dismiss after 8 seconds
    const timer = setTimeout(() => {
      onReset()
    }, 8000)

    return () => clearTimeout(timer)
  }, [onReset])

  return (
    <div className="mt-6 flex flex-col items-center justify-center py-12 space-y-6 animate-in fade-in zoom-in duration-500">
      {/* Animated Success Icon */}
      <div className="relative">
        {/* Outer pulse rings */}
        <div className="absolute inset-0 rounded-full bg-emerald-500/20 animate-ping" />
        <div className="absolute inset-0 rounded-full bg-emerald-500/10 animate-pulse" />

        {/* Inner icon */}
        <div className="relative bg-gradient-to-r from-emerald-500 to-teal-500 rounded-full p-6 shadow-2xl shadow-emerald-500/30">
          <CheckCircle className="w-16 h-16 text-white" strokeWidth={2.5} />
        </div>
      </div>

      {/* Success Heading */}
      <div className="text-center space-y-2">
        <h2 className="text-2xl md:text-3xl font-bold text-slate-900">
          Request Received!
        </h2>
        <p className="text-sm text-slate-600 max-w-md">
          Your security audit request has been submitted successfully
        </p>
      </div>

      {/* Email Confirmation */}
      <div className="w-full max-w-md p-4 bg-emerald-50 border-2 border-emerald-200 rounded-xl">
        <div className="flex items-center gap-3">
          <div className="bg-emerald-100 rounded-full p-2">
            <Mail className="w-5 h-5 text-emerald-700" />
          </div>
          <div className="flex-1">
            <p className="text-xs text-emerald-700 font-medium">
              Full report will be sent to:
            </p>
            <p className="text-sm font-semibold text-emerald-900 truncate">
              {email}
            </p>
          </div>
        </div>
      </div>

      {/* Details */}
      <div className="text-center space-y-3 max-w-md">
        <p className="text-sm text-slate-700">
          Our security experts will analyze your domain and send a detailed
          report with recommendations within{" "}
          <span className="font-semibold text-slate-900">24-48 hours</span>.
        </p>

        <div className="pt-4 space-y-2">
          <p className="text-xs text-slate-500">What happens next:</p>
          <ul className="text-xs text-slate-600 space-y-1.5">
            <li className="flex items-center gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-orange-500" />
              Deep analysis of your domain security
            </li>
            <li className="flex items-center gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-orange-500" />
              Expert recommendations and remediation steps
            </li>
            <li className="flex items-center gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-orange-500" />
              Email deliverability assessment
            </li>
          </ul>
        </div>
      </div>

      {/* Action Buttons */}
      <div className="w-full max-w-md pt-4 space-y-3">
        <button
          onClick={onReset}
          className="w-full py-3 px-6 bg-gradient-to-r from-orange-500 to-amber-500 text-white font-semibold text-sm rounded-lg shadow-lg shadow-orange-500/30 hover:shadow-xl hover:shadow-orange-500/40 hover:from-orange-600 hover:to-amber-600 active:scale-[0.99] transition-all duration-300 flex items-center justify-center gap-2 group"
        >
          <span>Scan Another Domain</span>
          <ArrowRight className="w-4 h-4 group-hover:translate-x-0.5 transition-transform" />
        </button>

        <p className="text-xs text-slate-400 text-center">
          This page will automatically close in 8 seconds
        </p>
      </div>
    </div>
  )
}
