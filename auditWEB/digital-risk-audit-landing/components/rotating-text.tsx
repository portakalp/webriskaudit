"use client"

import { useState, useEffect } from "react"

const painPoints = ["losing clients", "landing in spam", "facing GDPR fines", "exposed to bots"]

export function RotatingText() {
  const [currentIndex, setCurrentIndex] = useState(0)
  const [isAnimating, setIsAnimating] = useState(false)

  useEffect(() => {
    const interval = setInterval(() => {
      setIsAnimating(true)

      setTimeout(() => {
        setCurrentIndex((prev) => (prev + 1) % painPoints.length)
        setIsAnimating(false)
      }, 300)
    }, 3000)

    return () => clearInterval(interval)
  }, [])

  return (
    <span className="inline-grid text-center align-bottom justify-items-center">
      {painPoints.map((text, index) => (
        <span
          key={text}
          className={`col-start-1 row-start-1 text-orange-500 transition-opacity duration-300 ease-out whitespace-nowrap ${
            index === currentIndex
              ? (isAnimating ? "opacity-0" : "opacity-100")
              : "opacity-0 pointer-events-none"
          }`}
          aria-hidden={index !== currentIndex}
        >
          {text}
        </span>
      ))}
    </span>
  )
}
