"""Interpret datetime-local form values in the application's configured timezone."""
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from .parsers import parse_iso

def parse_form_datetime(value, timezone_name):
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=ZoneInfo(timezone_name))
    return parsed.astimezone(timezone.utc)
