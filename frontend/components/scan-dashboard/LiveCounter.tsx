"use client"

import { useState, useEffect } from "react"

/**
 * Custom hook for animating counter values with smooth easing
 * @param target - The target number to count to
 * @param duration - Animation duration in milliseconds (default: 1000)
 * @returns The current animated count value
 */
export function useAnimatedCounter(target: number, duration: number = 1000): number {
  const [count, setCount] = useState(0)

  useEffect(() => {
    let startTime: number
    let animationFrame: number

    const animate = (currentTime: number) => {
      if (!startTime) startTime = currentTime
      const progress = Math.min((currentTime - startTime) / duration, 1)

      // Ease-out cubic for smooth deceleration
      const eased = 1 - Math.pow(1 - progress, 3)
      setCount(Math.round(eased * target))

      if (progress < 1) {
        animationFrame = requestAnimationFrame(animate)
      }
    }

    animationFrame = requestAnimationFrame(animate)
    return () => cancelAnimationFrame(animationFrame)
  }, [target, duration])

  return count
}
