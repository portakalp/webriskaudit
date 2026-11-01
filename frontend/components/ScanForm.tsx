"use client"

import type React from "react"
import { useState } from "react"
import { Globe, Mail, ArrowRight, Loader2, Lock, AlertCircle } from "lucide-react"
import { isValidEmail, isValidDomain, sanitizeInput, cleanDomain } from "@/lib/validation"

interface ScanFormProps {
  onSubmit: (email: string, domain: string) => void
  isLoading?: boolean
}

export function ScanForm({ onSubmit, isLoading = false }: ScanFormProps) {
  const [website, setWebsite] = useState("")
  const [email, setEmail] = useState("")
  const [focusedField, setFocusedField] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)

    // Sanitize inputs
    const sanitizedEmail = sanitizeInput(email)
    const sanitizedWebsite = sanitizeInput(website)

    // Validate empty fields
    if (!sanitizedEmail || !sanitizedWebsite) {
      setError("Please fill in all fields")
      return
    }

    // Validate email format
    if (!isValidEmail(sanitizedEmail)) {
      setError("Please enter a valid email address")
      return
    }

    // Validate domain format
    if (!isValidDomain(sanitizedWebsite)) {
      setError("Please enter a valid domain (e.g., example.com)")
      return
    }

    // Clean domain and call parent's onSubmit callback
    const cleanedDomain = cleanDomain(sanitizedWebsite)
    onSubmit(sanitizedEmail, cleanedDomain)
  }

  return (
    <form onSubmit={handleSubmit} className="mt-6 space-y-4">
      {/* Error Message */}
      {error && (
        <div className="p-3 bg-red-50 border border-red-200 rounded-lg flex items-start gap-2 animate-in fade-in duration-200">
          <AlertCircle className="w-4 h-4 text-red-600 flex-shrink-0 mt-0.5" />
          <p className="text-xs text-red-700 font-medium">{error}</p>
        </div>
      )}

      <div className="space-y-1.5">
        <label className="text-xs font-medium text-slate-700 pl-1">Website URL</label>
        <div className="relative group">
          <Globe
            className={`absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 transition-colors ${
              focusedField === "website" ? "text-orange-500" : "text-slate-400"
            }`}
          />
          <input
            type="text"
            placeholder="yourdomain.com"
            value={website}
            onChange={(e) => setWebsite(e.target.value)}
            onFocus={() => setFocusedField("website")}
            onBlur={() => setFocusedField(null)}
            required
            disabled={isLoading}
            className="w-full pl-11 pr-10 py-3 bg-slate-50 border border-slate-200 rounded-lg text-slate-900 text-sm placeholder:text-slate-400 placeholder:font-mono focus:outline-none focus:border-orange-400 focus:ring-2 focus:ring-orange-100 focus:bg-white transition-all disabled:opacity-60 disabled:cursor-not-allowed"
          />
          <Lock className="absolute right-3.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-300" />
        </div>
      </div>

      <div className="space-y-1.5">
        <label className="text-xs font-medium text-slate-700 pl-1">Email Address</label>
        <div className="relative group">
          <Mail
            className={`absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 transition-colors ${
              focusedField === "email" ? "text-orange-500" : "text-slate-400"
            }`}
          />
          <input
            type="email"
            placeholder="name@company.com"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            onFocus={() => setFocusedField("email")}
            onBlur={() => setFocusedField(null)}
            required
            disabled={isLoading}
            className="w-full pl-11 pr-10 py-3 bg-slate-50 border border-slate-200 rounded-lg text-slate-900 text-sm placeholder:text-slate-400 placeholder:font-mono focus:outline-none focus:border-orange-400 focus:ring-2 focus:ring-orange-100 focus:bg-white transition-all disabled:opacity-60 disabled:cursor-not-allowed"
          />
          <Lock className="absolute right-3.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-300" />
        </div>
      </div>

      <button
        type="submit"
        disabled={isLoading}
        className="relative w-full py-3.5 px-6 mt-4 bg-gradient-to-r from-orange-500 to-amber-500 text-white font-semibold text-sm rounded-lg shadow-lg shadow-orange-500/30 hover:shadow-xl hover:shadow-orange-500/40 hover:from-orange-600 hover:to-amber-600 active:scale-[0.99] transition-all duration-300 disabled:opacity-70 disabled:cursor-not-allowed flex items-center justify-center gap-2 group"
      >
        {isLoading ? (
          <>
            <Loader2 className="w-4 h-4 animate-spin" />
            <span>Scanning...</span>
          </>
        ) : (
          <>
            <span className="flex items-center gap-2">
              <span>Get My Free Risk Score</span>
              <ArrowRight className="w-4 h-4 transition-transform group-hover:translate-x-1" />
            </span>
          </>
        )}
      </button>
    </form>
  )
}
