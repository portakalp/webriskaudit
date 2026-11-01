"""
SecurityAuditor.py - Production-Ready Website Security Scanner
Follows 3 Immutable Laws:
1. Real Browser Identity (Cloudflare Bypass)
2. Strict Scoring Math (No Errors)
3. Resilience & Benefit of Doubt
"""

import requests
import socket
import ssl
import dns.resolver
import logging
import time
from urllib.parse import urlparse
from datetime import datetime
from pydnsbl import DNSBLIpChecker

# Setup logging
logger = logging.getLogger(__name__)

# ============================================================================
# LAW #1: REAL BROWSER IDENTITY - Full Chrome Headers
# ============================================================================
CHROME_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9',
    'Accept-Encoding': 'gzip, deflate, br',
    'DNT': '1',
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'none',
    'Sec-Fetch-User': '?1',
    'Cache-Control': 'max-age=0',
    'Referer': 'https://www.google.com/'
}

# Timeouts
TIMEOUT = 30  # HTTP requests - increased for production datacenter latency
DNS_TIMEOUT = 5  # DNS lookups

# ============================================================================
# LAW #2: STRICT SCORING MATH - Explicit Point Values
# ============================================================================
SCORING = {
    "email": {
        "spf": 10,
        "dmarc": 10,
        "dkim": 5,
        "blacklist": 10
    },
    "server": {
        "ssl": 10,
        "waf": 10,
        "server_identity": 10,
        "security_headers": 20
    },
    "compliance": {
        "privacy_policy": 10
    }
}

# Partial credit per security header when fewer than 4 are present
POINTS_PER_HEADER = 5

# Each SCORING value is the most a check can award, so maxima are plain sums
CATEGORY_MAX = {category: sum(checks.values()) for category, checks in SCORING.items()}
MAX_SCORE = sum(CATEGORY_MAX.values())

# Privacy Policy Paths (Multi-Language Support for Europe)
PRIVACY_PATHS = [
    # English
    '/privacy-policy', '/privacy', '/legal/privacy', '/legal', '/terms',
    
    # German (Deutsch)
    '/datenschutz', '/datenschutzerklaerung', '/impressum', '/rechtliches',
    
    # French (Français)
    '/politique-de-confidentialite', '/confidentialite', '/vie-privee', '/mentions-legales',
    
    # Spanish (Español)
    '/politica-de-privacidad', '/privacidad', '/aviso-legal',
    
    # Italian (Italiano)
    '/informativa-privacy', '/privacy-policy', '/note-legali',
    
    # Dutch (Nederlands)
    '/privacybeleid', '/privacyverklaring',
    
    # Portuguese (Português)
    '/politica-de-privacidade', '/privacidade',
    
    # Polish (Polski)
    '/polityka-prywatnosci', '/prywatnosc',
    
    # Turkish (Türkçe)
    '/gizlilik-politikasi', '/kvkk', '/kisisel-verilerin-korunmasi', '/aydinlatma-metni',

    # Swedish (Svenska)
    '/integritetspolicy', '/personuppgiftspolicy',

    # Danish (Dansk)
    '/privatlivspolitik', '/persondatapolitik',

    # Finnish (Suomi)
    '/tietosuoja', '/tietosuojaseloste',

    # Norwegian (Norsk)
    '/personvern', '/personvernerklaering',
    
    # Romanian (Română)
    '/politica-de-confidentialitate', '/confidentialitate',

    # Greek (Ελληνικά)
    '/politiki-aporritou', '/prostasia-dedomenon',

    # Czech (Čeština)
    '/ochrana-osobnich-udaju', '/zasady-ochrany-osobnich-udaju',

    # Hungarian (Magyar)
    '/adatvedelmi-nyilatkozat', '/adatvedelem',
    
    # GDPR / General
    '/gdpr', '/dsgvo', '/rgpd'
]

# Common DKIM Selectors
DKIM_SELECTORS = ['default', 'google', 's1', 's2', 'k1', 'dkim', 'selector1', 'selector2']

# Security Headers (5 required)
REQUIRED_HEADERS = [
    'strict-transport-security',
    'content-security-policy',
    'x-frame-options',
    'permissions-policy',
    'referrer-policy'
]

# Cloudflare IP Prefixes
CLOUDFLARE_IP_PREFIXES = ['172.67', '104.21', '104.16', '104.17', '104.18', '104.19']

# Server Header Values
MASKED_SERVER_VALUES = ['cloudflare', 'cdn77', 'akamai', 'fastly', 'aws', 'cloudfront']
DISCLOSED_SERVER_VALUES = ['apache', 'nginx', 'microsoft-iis', 'express', 'node.js', 'tomcat']


# ============================================================================
# HELPER FUNCTIONS - Cloudflare Bypass with Retry Logic
# ============================================================================

def fetch_with_retry(url: str, headers: dict, max_retries: int = 3):
    """
    Fetch URL with exponential backoff retry logic to bypass Cloudflare blocks.

    Args:
        url: Target URL to fetch
        headers: HTTP headers to use
        max_retries: Maximum number of retry attempts

    Returns:
        Response object if successful, None if all retries failed
    """
    for attempt in range(max_retries):
        try:
            response = requests.get(url, headers=headers, timeout=TIMEOUT, allow_redirects=True)

            # Check if Cloudflare challenge or 403
            if response.status_code == 403 or 'cloudflare' in response.text.lower():
                wait_time = 2 ** attempt  # Exponential backoff: 1s, 2s, 4s
                logger.info(f"Cloudflare detected for {url}, waiting {wait_time}s before retry {attempt + 1}/{max_retries}")
                time.sleep(wait_time)
                continue

            return response

        except requests.exceptions.Timeout:
            if attempt < max_retries - 1:
                wait_time = 2 ** attempt
                logger.warning(f"Timeout for {url} on attempt {attempt + 1}, retrying in {wait_time}s...")
                time.sleep(wait_time)
            else:
                logger.error(f"Timeout for {url} after {max_retries} attempts")
                raise
        except Exception as e:
            logger.error(f"Fetch failed for {url}: {str(e)}")
            raise

    return None


class SecurityAuditor:
    """
    Passive security auditor for domains.
    Returns simplified JSON structure with accurate scoring.
    """

    def __init__(self, domain: str):
        """
        Initialize auditor with domain normalization.

        Args:
            domain: Raw domain input (with/without protocol, www, ports)
        """
        self.domain = self._normalize_domain(domain)
        self._cached_response = None

    def _normalize_domain(self, domain: str) -> str:
        """Extract clean domain from various input formats."""
        # Remove protocol
        if domain.startswith(('http://', 'https://')):
            parsed = urlparse(domain)
            domain = parsed.netloc or parsed.path.split('/')[0]
        else:
            domain = domain.split('/')[0]

        # Remove www prefix
        if domain.startswith("www."):
            domain = domain[4:]

        # Remove port
        if ":" in domain:
            domain = domain.split(":")[0]

        return domain.lower()

    def _get_http_response(self, url: str = None) -> requests.Response:
        """
        Get HTTP response with proper headers and caching.
        Uses CHROME_HEADERS for all requests (LAW #1).
        """
        if url is None:
            url = f"https://{self.domain}"

        # Use cached response for main domain
        if url == f"https://{self.domain}" and self._cached_response:
            return self._cached_response

        try:
            response = requests.get(url, headers=CHROME_HEADERS, timeout=TIMEOUT, allow_redirects=True)

            # Cache main domain response
            if url == f"https://{self.domain}":
                self._cached_response = response

            return response
        except Exception:
            return None

    def _calculate_status(self, score: int, max_score: int) -> str:
        """Calculate category status based on percentage."""
        percentage = (score / max_score * 100) if max_score > 0 else 0
        if percentage >= 80:
            return "SECURE"
        elif percentage >= 50:
            return "MODERATE"
        else:
            return "CRITICAL"

    # ========================================================================
    # EMAIL SECURITY CHECKS
    # ========================================================================

    def _check_spf(self) -> dict:
        """
        Check SPF record via DNS TXT lookup.
        LAW #2: 10 points if valid, 0 if missing
        LAW #3: 10 points on timeout (benefit of doubt)
        """
        try:
            answers = dns.resolver.resolve(self.domain, 'TXT', lifetime=DNS_TIMEOUT)
            spf_record = None

            for rdata in answers:
                txt = rdata.to_text().strip('"')
                if 'v=spf1' in txt:
                    spf_record = txt
                    break

            if spf_record:
                # Check for insecure +all
                if '+all' in spf_record:
                    return {
                        "found": False,
                        "points": 0,
                        "record": spf_record,
                        "reason": "insecure (+all)"
                    }
                else:
                    return {
                        "found": True,
                        "points": SCORING["email"]["spf"],
                        "record": spf_record[:100]  # Truncate for brevity
                    }
            else:
                return {
                    "found": False,
                    "points": 0,
                    "reason": "missing"
                }

        except (dns.resolver.Timeout, dns.resolver.NoNameservers, dns.resolver.NoAnswer):
            # LAW #3: Benefit of doubt on timeout
            return {
                "found": True,
                "points": SCORING["email"]["spf"],
                "error": "timeout",
                "assumed": True
            }
        except Exception:
            # LAW #3: Benefit of doubt on unknown errors
            return {
                "found": True,
                "points": SCORING["email"]["spf"],
                "error": "dns_error",
                "assumed": True
            }

    def _check_dmarc(self) -> dict:
        """
        Check DMARC record via DNS TXT lookup.
        LAW #2: 10 points if reject/quarantine, 0 if none/missing
        LAW #3: 10 points on timeout (benefit of doubt)
        """
        try:
            answers = dns.resolver.resolve(f"_dmarc.{self.domain}", 'TXT', lifetime=DNS_TIMEOUT)
            dmarc_record = answers[0].to_text().strip('"')

            # Extract policy
            policy = None
            if 'p=reject' in dmarc_record:
                policy = 'reject'
            elif 'p=quarantine' in dmarc_record:
                policy = 'quarantine'
            elif 'p=none' in dmarc_record:
                policy = 'none'

            if policy in ['reject', 'quarantine']:
                return {
                    "found": True,
                    "points": SCORING["email"]["dmarc"],
                    "policy": policy,
                    "record": dmarc_record[:100]
                }
            else:
                return {
                    "found": True,
                    "points": 0,
                    "policy": policy or "unknown",
                    "reason": "weak policy"
                }

        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return {
                "found": False,
                "points": 0,
                "reason": "missing"
            }
        except (dns.resolver.Timeout, dns.resolver.NoNameservers):
            # LAW #3: Benefit of doubt on timeout
            return {
                "found": True,
                "points": SCORING["email"]["dmarc"],
                "error": "timeout",
                "assumed": True
            }
        except Exception:
            # LAW #3: Benefit of doubt on unknown errors
            return {
                "found": True,
                "points": SCORING["email"]["dmarc"],
                "error": "dns_error",
                "assumed": True
            }

    def _check_dkim(self) -> dict:
        """
        Check DKIM via DNS lookup of common selectors.
        LAW #2: 5 points if found, 0 if missing
        LAW #3: 5 points on timeout (benefit of doubt)
        """
        try:
            for selector in DKIM_SELECTORS:
                try:
                    query = f"{selector}._domainkey.{self.domain}"
                    answers = dns.resolver.resolve(query, 'TXT', lifetime=DNS_TIMEOUT)

                    for rdata in answers:
                        txt = rdata.to_text().strip('"')
                        # Look for DKIM indicators
                        if 'v=DKIM1' in txt or 'k=rsa' in txt or 'p=' in txt:
                            return {
                                "found": True,
                                "points": SCORING["email"]["dkim"],
                                "selector": selector,
                                "record": txt[:100]
                            }

                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                    # Try next selector
                    continue
                except dns.resolver.Timeout:
                    # LAW #3: Timeout on any selector = benefit of doubt
                    return {
                        "found": True,
                        "points": SCORING["email"]["dkim"],
                        "error": "timeout",
                        "assumed": True
                    }

            # No selector found
            return {
                "found": False,
                "points": 0,
                "reason": "no selector found"
            }

        except Exception:
            # LAW #3: Benefit of doubt on unknown errors
            return {
                "found": True,
                "points": SCORING["email"]["dkim"],
                "error": "dns_error",
                "assumed": True
            }

    def _check_blacklist(self) -> dict:
        """
        Check IP reputation using DNSBLIpChecker.
        LAW #2: 10 points if clean, 0 if blacklisted
        LAW #3: 10 points on timeout (benefit of doubt)
        """
        try:
            ip = socket.gethostbyname(self.domain)
            checker = DNSBLIpChecker()
            result = checker.check(ip)

            if result.blacklisted:
                return {
                    "clean": False,
                    "points": 0,
                    "ip": ip,
                    "blacklisted_on": result.blacklisted_on
                }
            else:
                return {
                    "clean": True,
                    "points": SCORING["email"]["blacklist"],
                    "ip": ip
                }

        except (socket.timeout, socket.gaierror):
            # LAW #3: Benefit of doubt on timeout
            return {
                "clean": True,
                "points": SCORING["email"]["blacklist"],
                "error": "timeout",
                "assumed": True
            }
        except Exception:
            # LAW #3: Benefit of doubt on unknown errors
            return {
                "clean": True,
                "points": SCORING["email"]["blacklist"],
                "error": "check_failed",
                "assumed": True
            }

    # ========================================================================
    # SERVER SECURITY CHECKS
    # ========================================================================

    def _check_ssl(self) -> dict:
        """
        Check SSL certificate validity and expiration.
        LAW #2: 10 points if valid AND >30 days remaining
        LAW #3: 10 points on timeout (benefit of doubt)
        """
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((self.domain, 443), timeout=TIMEOUT) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_remaining = (expiry_date - datetime.now()).days

                    if days_remaining < 0:
                        # Expired
                        return {
                            "valid": False,
                            "points": 0,
                            "days_remaining": days_remaining,
                            "expiry_date": expiry_date.isoformat(),
                            "reason": "expired"
                        }
                    elif days_remaining <= 30:
                        # Valid but expiring soon
                        return {
                            "valid": False,
                            "points": 0,
                            "days_remaining": days_remaining,
                            "expiry_date": expiry_date.isoformat(),
                            "reason": "expiring_soon"
                        }
                    else:
                        # Valid and good expiry
                        return {
                            "valid": True,
                            "points": SCORING["server"]["ssl"],
                            "days_remaining": days_remaining,
                            "expiry_date": expiry_date.isoformat()
                        }

        except ssl.SSLError:
            # Actual SSL error (certificate invalid)
            return {
                "valid": False,
                "points": 0,
                "error": "ssl_error"
            }
        except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError):
            # LAW #3: Benefit of doubt on timeout/connection errors
            return {
                "valid": True,
                "points": SCORING["server"]["ssl"],
                "error": "timeout",
                "assumed": True
            }
        except Exception:
            # LAW #3: Benefit of doubt on unknown errors
            return {
                "valid": True,
                "points": SCORING["server"]["ssl"],
                "error": "check_failed",
                "assumed": True
            }

    def _check_waf(self) -> dict:
        """
        Detect WAF via IP ranges and headers.
        LAW #2: 10 points if detected, 0 if not
        LAW #3: 0 points on timeout (cannot assume WAF exists)
        """
        waf_type = None

        # Method 1: Check IP ranges (Cloudflare)
        try:
            ip = socket.gethostbyname(self.domain)
            for prefix in CLOUDFLARE_IP_PREFIXES:
                if ip.startswith(prefix):
                    return {
                        "detected": True,
                        "points": SCORING["server"]["waf"],
                        "type": "Cloudflare",
                        "method": "dns",
                        "ip": ip
                    }
        except Exception:
            pass

        # Method 2: Check HTTP headers
        response = self._get_http_response()
        if response:
            headers = {k.lower(): v for k, v in response.headers.items()}

            # Cloudflare
            if 'cf-ray' in headers or 'cloudflare' in headers.get('server', '').lower():
                waf_type = "Cloudflare"
            # Sucuri
            elif 'x-sucuri-id' in headers:
                waf_type = "Sucuri"
            # AWS Shield / CloudFront
            elif 'x-amz-cf-id' in headers:
                waf_type = "AWS CloudFront"
            # Akamai
            elif 'akamai' in headers.get('server', '').lower():
                waf_type = "Akamai"

            if waf_type:
                return {
                    "detected": True,
                    "points": SCORING["server"]["waf"],
                    "type": waf_type,
                    "method": "header"
                }

        # No WAF detected
        return {
            "detected": False,
            "points": 0,
            "reason": "not_detected"
        }

    def _check_server_identity(self) -> dict:
        """
        Check if server identity is masked.
        LAW #2: 10 points if masked, 0 if disclosed
        LAW #3: 10 points on timeout (benefit of doubt)
        """
        response = self._get_http_response()

        if not response:
            # LAW #3: Benefit of doubt on timeout
            return {
                "masked": True,
                "points": SCORING["server"]["server_identity"],
                "error": "timeout",
                "assumed": True
            }

        headers = {k.lower(): v for k, v in response.headers.items()}
        server_header = headers.get('server', '').lower()

        # Empty/missing = masked
        if not server_header:
            return {
                "masked": True,
                "points": SCORING["server"]["server_identity"],
                "header": "empty"
            }

        # Check for masked values (CDN/WAF)
        if any(masked in server_header for masked in MASKED_SERVER_VALUES):
            return {
                "masked": True,
                "points": SCORING["server"]["server_identity"],
                "header": server_header
            }

        # Check for disclosed values (web servers)
        if any(disclosed in server_header for disclosed in DISCLOSED_SERVER_VALUES):
            return {
                "masked": False,
                "points": 0,
                "header": server_header,
                "reason": "server_disclosed"
            }

        # Unknown value = benefit of doubt
        return {
            "masked": True,
            "points": SCORING["server"]["server_identity"],
            "header": server_header,
            "reason": "unknown"
        }

    def _check_security_headers(self) -> dict:
        """
        Check 5 critical security headers.
        LAW #2: count >= 4 = 20 pts, else count * 5 pts
        LAW #3: 20 points on timeout (benefit of doubt)
        """
        response = self._get_http_response()

        if not response:
            # LAW #3: Benefit of doubt on timeout
            return {
                "count": 5,
                "points": SCORING["server"]["security_headers"],
                "headers": {h: True for h in REQUIRED_HEADERS},
                "error": "timeout",
                "assumed": True
            }

        headers = {k.lower(): v for k, v in response.headers.items()}
        found_headers = {}
        count = 0

        for required in REQUIRED_HEADERS:
            # Check for header (or legacy alternative for permissions-policy)
            if required in headers:
                found_headers[required] = True
                count += 1
            elif required == 'permissions-policy' and 'feature-policy' in headers:
                # Legacy feature-policy counts as permissions-policy
                found_headers[required] = True
                count += 1
            else:
                found_headers[required] = False

        # LAW #2: Strict scoring math
        if count >= 4:
            points = SCORING["server"]["security_headers"]
        else:
            points = count * POINTS_PER_HEADER

        return {
            "count": count,
            "points": points,
            "headers": found_headers
        }

    # ========================================================================
    # COMPLIANCE CHECKS
    # ========================================================================

    def _check_privacy_policy(self) -> dict:
        """
        Check for privacy policy page.
        LAW #2: 10 points if found, 0 if missing
        LAW #3: 10 points on timeout/block (benefit of doubt)
        """
        consecutive_failures = 0
        MAX_CONSECUTIVE_FAILURES = 3

        for path in PRIVACY_PATHS:
            try:
                url = f"https://{self.domain}{path}"

                # Use retry logic to bypass Cloudflare blocks
                response = fetch_with_retry(url, CHROME_HEADERS)

                if response is None:
                    logger.warning(f"Privacy check: {url} → All retries failed")
                    consecutive_failures += 1
                    if consecutive_failures >= MAX_CONSECUTIVE_FAILURES:
                         logger.warning(f"Aborting privacy check due to {consecutive_failures} consecutive failures (likely WAF/Cloudflare block).")
                         return {
                            "found": True,
                            "points": SCORING["compliance"]["privacy_policy"],
                            "error": "too_many_blocks",
                            "assumed": True
                        }
                    continue

                # Debug logging
                logger.info(f"Privacy check: {url} → Status {response.status_code}, Length {len(response.content)} bytes")

                if response.status_code == 200:
                    # Check if it's actually privacy policy content (not Cloudflare challenge)
                    content_lower = response.text.lower()

                    if 'challenge' in content_lower and 'cloudflare' in content_lower:
                        logger.warning(f"Cloudflare challenge page detected for {url}")
                        consecutive_failures += 1
                        if consecutive_failures >= MAX_CONSECUTIVE_FAILURES:
                            logger.warning(f"Aborting privacy check due to {consecutive_failures} consecutive Cloudflare challenges.")
                            return {
                                "found": True,
                                "points": SCORING["compliance"]["privacy_policy"],
                                "error": "cloudflare_block",
                                "assumed": True
                            }
                        continue
                    
                    # Reset failure counter on success (though we return immediately)
                    consecutive_failures = 0
                    
                    logger.info(f"Privacy policy FOUND at {url}")
                    return {
                        "found": True,
                        "points": SCORING["compliance"]["privacy_policy"],
                        "url": path
                    }
                
                # If we get here (e.g. 404), reset consecutive failures because the server IS responding properly
                if response.status_code == 404:
                    consecutive_failures = 0

            except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
                logger.warning(f"Privacy check timeout/connection error for {url}: {str(e)}")
                # LAW #3: Benefit of doubt on timeout
                return {
                    "found": True,
                    "points": SCORING["compliance"]["privacy_policy"],
                    "error": "timeout",
                    "assumed": True
                }
            except Exception as e:
                logger.error(f"Privacy check failed for {url}: {str(e)}")
                # Try next path
                continue

        # Not found on any path
        logger.warning(f"Privacy policy NOT FOUND for {self.domain} on any path")
        return {
            "found": False,
            "points": 0,
            "reason": "not_found"
        }

    # ========================================================================
    # MAIN ORCHESTRATOR
    # ========================================================================

    def run_audit(self) -> dict:
        """
        Execute all security checks and return final report.
        Returns simplified 3-level structure (domain → categories → details).
        """
        # Run all checks
        email_details = {
            "spf": self._check_spf(),
            "dmarc": self._check_dmarc(),
            "dkim": self._check_dkim(),
            "blacklist": self._check_blacklist()
        }

        server_details = {
            "ssl": self._check_ssl(),
            "waf": self._check_waf(),
            "server_identity": self._check_server_identity(),
            "security_headers": self._check_security_headers()
        }

        compliance_details = {
            "privacy_policy": self._check_privacy_policy()
        }

        # Calculate category scores (LAW #2: Strict math)
        email_score = sum(d["points"] for d in email_details.values())
        server_score = sum(d["points"] for d in server_details.values())
        compliance_score = sum(d["points"] for d in compliance_details.values())

        # Calculate category status
        email_status = self._calculate_status(email_score, CATEGORY_MAX["email"])
        server_status = self._calculate_status(server_score, CATEGORY_MAX["server"])
        compliance_status = self._calculate_status(compliance_score, CATEGORY_MAX["compliance"])

        # Overall score is normalized to 0-100
        earned = email_score + server_score + compliance_score

        # Return simplified structure
        return {
            "domain": self.domain,
            "score": round(100 * earned / MAX_SCORE),
            "email_security": {
                "score": email_score,
                "max": CATEGORY_MAX["email"],
                "status": email_status,
                "details": email_details
            },
            "server_security": {
                "score": server_score,
                "max": CATEGORY_MAX["server"],
                "status": server_status,
                "details": server_details
            },
            "compliance": {
                "score": compliance_score,
                "max": CATEGORY_MAX["compliance"],
                "status": compliance_status,
                "details": compliance_details
            }
        }


# ============================================================================
# CLI TESTING
# ============================================================================
if __name__ == '__main__':
    import sys
    import json

    domain = sys.argv[1] if len(sys.argv) > 1 else "google.com"
    auditor = SecurityAuditor(domain)
    result = auditor.run_audit()
    print(json.dumps(result, indent=2))
