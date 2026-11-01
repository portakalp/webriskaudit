"""Structured logging: one JSON object per line on stderr.

Each line carries ``severity`` (Cloud Logging's field for the level) and
``time``, which Cloud Logging reads from a JSON line, besides ``level`` and
``message``.
"""

import json
import logging
from datetime import UTC, datetime

PACKAGE_LOGGER = "webriskaudit"
UVICORN_LOGGERS = ("uvicorn", "uvicorn.error", "uvicorn.asgi")
"""uvicorn's own loggers, except the access log; "uvicorn.error" is its general log."""


def severity(level: int) -> str:
    """Cloud Logging's LogSeverity for a logging level."""
    if level >= logging.CRITICAL:
        return "CRITICAL"
    if level >= logging.ERROR:
        return "ERROR"
    if level >= logging.WARNING:
        return "WARNING"
    if level >= logging.INFO:
        return "INFO"
    if level >= logging.DEBUG:
        return "DEBUG"
    return "DEFAULT"


class JsonFormatter(logging.Formatter):
    """One JSON object per record; ``extra={"fields": {...}}`` adds top-level keys."""

    def format(self, record: logging.LogRecord) -> str:
        entry: dict[str, object] = {
            "time": datetime.fromtimestamp(record.created, UTC).isoformat(timespec="milliseconds"),
            "severity": severity(record.levelno),
            "level": record.levelname.lower(),
            "logger": record.name,
            "message": record.getMessage(),
        }
        fields = getattr(record, "fields", None)
        if isinstance(fields, dict):
            entry.update(fields)
        if record.exc_info:
            entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(entry, default=str, ensure_ascii=False)


def configure_logging(level: int = logging.INFO) -> None:
    """Send the package's logs to stderr as JSON lines. Safe to call more than once.

    uvicorn's own lines are switched to JSON as well, and its access log is
    switched off because it records client addresses, which this service
    does not log.
    """
    logger = logging.getLogger(PACKAGE_LOGGER)
    if not any(isinstance(h.formatter, JsonFormatter) for h in logger.handlers):
        handler = logging.StreamHandler()
        handler.setFormatter(JsonFormatter())
        logger.addHandler(handler)
    logger.setLevel(level)
    logger.propagate = False
    format_uvicorn_logs_as_json()
    logging.getLogger("uvicorn.access").disabled = True


def format_uvicorn_logs_as_json() -> None:
    """Make the handlers uvicorn set up for its own loggers write JSON lines.

    uvicorn configures its logging before it imports the application, so
    calling this while the application module is imported also covers
    uvicorn's first lines. Where uvicorn set up no handlers, this does nothing.
    """
    for name in UVICORN_LOGGERS:
        for handler in logging.getLogger(name).handlers:
            if not isinstance(handler.formatter, JsonFormatter):
                handler.setFormatter(JsonFormatter())
