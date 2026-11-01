"use client"

import { useState, useEffect } from "react"
import {
  Loader2, CheckCircle, Circle,
  Globe, Lock, Mail, ShieldCheck, Shield,
  FileCheck, AlertTriangle, FileText, Search, Calculator
} from "lucide-react"

interface ScanningAnimationProps {
  onComplete?: () => void
}

const securityTests = [
  { id: "dns", name: "DNS Resolution", icon: Globe, duration: 2000 },
  { id: "ssl", name: "SSL/TLS Certificate", icon: Lock, duration: 3000 },
  { id: "spf", name: "SPF Record", icon: Mail, duration: 2500 },
  { id: "dmarc", name: "DMARC Configuration", icon: ShieldCheck, duration: 2500 },
  { id: "waf", name: "WAF Detection", icon: Shield, duration: 4000 },
  { id: "headers", name: "Security Headers", icon: FileCheck, duration: 3000 },
  { id: "blacklist", name: "Blacklist Check", icon: AlertTriangle, duration: 2000 },
  { id: "compliance", name: "Privacy Policy", icon: FileText, duration: 2500 },
  { id: "typo", name: "Typosquatting Scan", icon: Search, duration: 2000 },
  { id: "score", name: "Calculating Score", icon: Calculator, duration: 1500 }
]

export function ScanningAnimation({ onComplete }: ScanningAnimationProps = {}) {
  const [completedTests, setCompletedTests] = useState<string[]>([])
  const [currentTestId, setCurrentTestId] = useState<string>("dns")
  const [progressPercentage, setProgressPercentage] = useState(0)

  useEffect(() => {
    let currentIndex = 0
    const totalDuration = securityTests.reduce((sum, t) => sum + t.duration, 0)
    let elapsedTime = 0

    const runNextTest = () => {
      if (currentIndex >= securityTests.length) {
        // Animation complete - notify parent after small delay
        if (onComplete) {
          setTimeout(onComplete, 500)
        }
        return
      }

      const test = securityTests[currentIndex]
      setCurrentTestId(test.id)

      setTimeout(() => {
        setCompletedTests(prev => [...prev, test.id])
        elapsedTime += test.duration
        setProgressPercentage(Math.round((elapsedTime / totalDuration) * 100))
        currentIndex++
        runNextTest()
      }, test.duration)
    }

    runNextTest()
  }, [onComplete])

  return (
    <div className="mt-6 py-8 space-y-6">
      {/* Overall Progress */}
      <div className="space-y-2">
        <div className="flex items-center justify-between text-sm">
          <span className="font-medium text-slate-700">Scanning Progress</span>
          <span className="text-slate-600">{progressPercentage}%</span>
        </div>
        <div className="h-2 w-full bg-slate-200 rounded-full overflow-hidden">
          <div
            className="h-full bg-gradient-to-r from-orange-500 to-amber-500 transition-all duration-300 ease-out"
            style={{ width: `${progressPercentage}%` }}
          />
        </div>
      </div>

      {/* Test List */}
      <div className="space-y-2">
        {securityTests.map(test => {
          const isCompleted = completedTests.includes(test.id)
          const isRunning = currentTestId === test.id
          const Icon = test.icon

          return (
            <div
              key={test.id}
              className={`flex items-center gap-3 p-3 rounded-lg transition-colors ${
                isRunning ? "bg-orange-50 border border-orange-200" : "bg-slate-50"
              }`}
            >
              {isCompleted ? (
                <CheckCircle className="w-5 h-5 text-emerald-600 flex-shrink-0" />
              ) : isRunning ? (
                <Loader2 className="w-5 h-5 text-orange-600 animate-spin flex-shrink-0" />
              ) : (
                <Circle className="w-5 h-5 text-slate-300 flex-shrink-0" />
              )}
              <Icon className="w-4 h-4 text-slate-600 flex-shrink-0" />
              <span className={`text-sm ${
                isCompleted ? "text-slate-400 line-through" :
                isRunning ? "text-slate-900 font-medium" :
                "text-slate-600"
              }`}>
                {test.name}
              </span>
            </div>
          )
        })}
      </div>

      <p className="text-xs text-slate-400 text-center">
        This may take 10-30 seconds depending on your domain configuration
      </p>
    </div>
  )
}
