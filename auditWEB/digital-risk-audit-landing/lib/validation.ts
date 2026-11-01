/**
 * Input validation and sanitization utilities for security
 */

/**
 * Validates email format
 * @param email - Email address to validate
 * @returns true if valid email format
 */
export const isValidEmail = (email: string): boolean => {
  // RFC 5322 compliant email regex (simplified)
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/
  return emailRegex.test(email) && email.length <= 254
}

/**
 * Validates domain/website format
 * @param domain - Domain to validate
 * @returns true if valid domain format
 */
export const isValidDomain = (domain: string): boolean => {
  // Remove protocol if present
  const cleaned = domain
    .replace(/^https?:\/\//, '')
    .replace(/^www\./, '')
    .trim()

  // Domain regex: alphanumeric, hyphens, dots, valid TLD
  // Must start and end with alphanumeric, can have hyphens in middle
  const domainRegex = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/

  return domainRegex.test(cleaned) && cleaned.length <= 253
}

/**
 * Sanitizes user input by removing dangerous characters and HTML
 * @param input - String to sanitize
 * @returns Sanitized string
 */
export const sanitizeInput = (input: string): string => {
  return input
    .replace(/<[^>]*>/g, '') // Remove HTML tags
    .replace(/[<>'"]/g, '') // Remove dangerous characters
    .replace(/javascript:/gi, '') // Remove javascript: protocol
    .replace(/on\w+=/gi, '') // Remove event handlers
    .trim()
}

/**
 * Cleans domain input by removing protocol and www
 * @param domain - Domain to clean
 * @returns Cleaned domain
 */
export const cleanDomain = (domain: string): string => {
  return domain
    .replace(/^https?:\/\//, '')
    .replace(/^www\./, '')
    .replace(/\/.*$/, '') // Remove path if present
    .trim()
    .toLowerCase()
}

/**
 * Validates that a string doesn't contain SQL injection patterns
 * @param input - String to check
 * @returns true if safe from SQL injection patterns
 */
export const isSafeSQLInput = (input: string): boolean => {
  // Check for common SQL injection patterns
  const sqlInjectionPatterns = [
    /(\s|^)(union|select|insert|update|delete|drop|create|alter|exec|execute)(\s|$)/i,
    /(\s|^)(or|and)(\s+\d+\s*=\s*\d+|\s+['"].*['"](\s*=\s*['"].*['"]))/i,
    /;.*(-{2}|\/\*)/,
    /'\s*or\s*'1'\s*=\s*'1/i,
    /'\s*or\s*1\s*=\s*1/i,
  ]

  return !sqlInjectionPatterns.some(pattern => pattern.test(input))
}

/**
 * Validates input length
 * @param input - String to validate
 * @param minLength - Minimum length (default: 1)
 * @param maxLength - Maximum length (default: 255)
 * @returns true if length is valid
 */
export const isValidLength = (input: string, minLength: number = 1, maxLength: number = 255): boolean => {
  const length = input.trim().length
  return length >= minLength && length <= maxLength
}
