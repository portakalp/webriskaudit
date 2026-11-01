/**
 * Client-side rate limiter to prevent API abuse
 */

interface RateLimitRecord {
  count: number
  resetTime: number
}

// In-memory storage for rate limit records
const rateLimitMap = new Map<string, RateLimitRecord>()

/**
 * Checks if a request should be rate limited
 * @param identifier - Unique identifier (e.g., email or IP)
 * @param maxRequests - Maximum number of requests allowed in the time window (default: 3)
 * @param windowMs - Time window in milliseconds (default: 60000 = 1 minute)
 * @returns true if request is allowed, false if rate limit exceeded
 */
export const checkRateLimit = (
  identifier: string,
  maxRequests: number = 3,
  windowMs: number = 60000
): boolean => {
  const now = Date.now()
  const record = rateLimitMap.get(identifier)

  // If no record exists or time window expired, allow and create new record
  if (!record || now > record.resetTime) {
    rateLimitMap.set(identifier, {
      count: 1,
      resetTime: now + windowMs
    })
    return true
  }

  // If max requests reached, deny
  if (record.count >= maxRequests) {
    return false
  }

  // Increment count and allow
  record.count++
  return true
}

/**
 * Gets remaining time until rate limit reset
 * @param identifier - Unique identifier
 * @returns Milliseconds until reset, or 0 if no limit active
 */
export const getResetTime = (identifier: string): number => {
  const record = rateLimitMap.get(identifier)
  if (!record) return 0

  const now = Date.now()
  const remaining = record.resetTime - now
  return remaining > 0 ? remaining : 0
}

/**
 * Manually reset rate limit for an identifier
 * @param identifier - Unique identifier to reset
 */
export const resetRateLimit = (identifier: string): void => {
  rateLimitMap.delete(identifier)
}

/**
 * Clear old rate limit records (cleanup)
 * Call this periodically to prevent memory leaks
 */
export const cleanupRateLimits = (): void => {
  const now = Date.now()
  for (const [key, record] of rateLimitMap.entries()) {
    if (now > record.resetTime) {
      rateLimitMap.delete(key)
    }
  }
}

// Auto-cleanup every 5 minutes
if (typeof window !== 'undefined') {
  setInterval(cleanupRateLimits, 5 * 60 * 1000)
}
