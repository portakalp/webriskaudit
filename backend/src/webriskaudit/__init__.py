"""WebRiskAudit: a passive security posture scanner for domains."""

__version__ = "2.0.0"

USER_AGENT = f"WebRiskAudit/{__version__} (+https://github.com/portakalp/webriskaudit)"

# Bumped whenever checks, weights or grade bands change, so two reports with
# the same methodology version are comparable.
METHODOLOGY_VERSION = "2026-11"
