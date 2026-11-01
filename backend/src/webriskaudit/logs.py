"""Structured logging: one JSON object per line on stderr."""

import json
import logging
from datetime import UTC, datetime

PACKAGE_LOGGER = "webriskaudit"


class JsonFormatter(logging.Formatter):
    """One JSON object per record; ``extra={"fields": {...}}`` adds top-level keys."""

    def format(self, record: logging.LogRecord) -> str:
        entry: dict[str, object] = {
            "time": datetime.fromtimestamp(record.created, UTC).isoformat(timespec="milliseconds"),
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

    uvicorn's access log is switched off because it records client addresses,
    which this service does not log.
    """
    logger = logging.getLogger(PACKAGE_LOGGER)
    if not any(isinstance(h.formatter, JsonFormatter) for h in logger.handlers):
        handler = logging.StreamHandler()
        handler.setFormatter(JsonFormatter())
        logger.addHandler(handler)
    logger.setLevel(level)
    logger.propagate = False
    logging.getLogger("uvicorn.access").disabled = True
