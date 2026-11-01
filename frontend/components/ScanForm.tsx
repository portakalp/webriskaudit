"use client"

import { useState, type FormEvent } from "react"
import { AlertCircle, ArrowRight, Globe } from "lucide-react"
import { validateDomain } from "@/lib/validation"

interface ScanFormProps {
  onSubmit: (domain: string) => void
  initialValue?: string
}

export function ScanForm({ onSubmit, initialValue = "" }: ScanFormProps) {
  const [website, setWebsite] = useState(initialValue)
  const [error, setError] = useState<string | null>(null)

  const handleSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()

    // Accept pasted URLs: reduce the input to a hostname, then validate it
    const result = validateDomain(website)
    if (!result.ok) {
      setError(result.error)
      return
    }

    setError(null)
    onSubmit(result.domain)
  }

  return (
    <form onSubmit={handleSubmit} noValidate className="mt-6 space-y-4">
      <div className="space-y-1.5">
        <label htmlFor="scan-domain" className="pl-1 text-sm font-medium text-slate-800">
          Domain
        </label>
        <div className="group relative">
          <Globe
            className="pointer-events-none absolute left-3.5 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500 transition-colors group-focus-within:text-orange-700"
            aria-hidden="true"
          />
          <input
            id="scan-domain"
            name="domain"
            type="text"
            inputMode="url"
            autoCapitalize="none"
            autoCorrect="off"
            spellCheck={false}
            placeholder="example.com"
            value={website}
            onChange={(event) => setWebsite(event.target.value)}
            required
            aria-invalid={error ? true : undefined}
            aria-describedby={error ? "scan-domain-hint scan-domain-error" : "scan-domain-hint"}
            className="w-full rounded-lg border border-slate-300 bg-slate-50 py-3 pl-11 pr-4 text-sm text-slate-900 transition-colors placeholder:font-mono placeholder:text-slate-500 focus:border-orange-700 focus:bg-white"
          />
        </div>
        <p id="scan-domain-hint" className="pl-1 text-xs text-slate-600">
          A domain or URL. The host is scanned as entered, so example.com and www.example.com are separate scans.
        </p>
      </div>

      {error && (
        <div
          id="scan-domain-error"
          role="alert"
          className="flex items-start gap-2 rounded-lg border border-red-200 bg-red-50 p-3 animate-in fade-in duration-200"
        >
          <AlertCircle className="mt-0.5 h-4 w-4 shrink-0 text-red-700" aria-hidden="true" />
          <p className="text-sm font-medium text-red-800">{error}</p>
        </div>
      )}

      <button
        type="submit"
        className="group flex w-full items-center justify-center gap-2 rounded-lg bg-gradient-to-r from-orange-700 to-amber-700 px-6 py-3.5 text-sm font-semibold text-white shadow-lg shadow-orange-700/25 transition-all duration-300 hover:from-orange-800 hover:to-amber-800 hover:shadow-xl active:scale-[0.99]"
      >
        Check domain
        <ArrowRight className="h-4 w-4 transition-transform group-hover:translate-x-1" aria-hidden="true" />
      </button>
    </form>
  )
}
