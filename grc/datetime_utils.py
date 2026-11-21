"""Consistent date and time formatting for Shadow Map GRC."""

from datetime import date, datetime, timezone
from zoneinfo import ZoneInfo


DISPLAY_TIMEZONE = ZoneInfo("Asia/Kolkata")


def _parse_datetime(value):
    """Parse supported date/time values without changing stored data."""
    if value is None or value == "":
        return None

    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, date):
        return value
    elif isinstance(value, (int, float)):
        try:
            parsed = datetime.fromtimestamp(value, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    else:
        raw = str(value).strip()
        if not raw:
            return None

        # Preserve date-only values without applying a timezone conversion.
        try:
            return date.fromisoformat(raw)
        except ValueError:
            pass

        try:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            try:
                return date.fromisoformat(raw)
            except ValueError:
                return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(DISPLAY_TIMEZONE)


def format_date(value):
    """Format a date as DD-MM-YYYY."""
    parsed = _parse_datetime(value)

    if parsed is None:
        return "—"

    if isinstance(parsed, date) and not isinstance(parsed, datetime):
        return parsed.strftime("%d-%m-%Y")

    return parsed.strftime("%d-%m-%Y")


def format_time(value):
    """Format a time as hh:mm AM/PM in IST."""
    parsed = _parse_datetime(value)

    if parsed is None or not isinstance(parsed, datetime):
        return "—"

    return parsed.strftime("%I:%M %p")


def format_datetime(value):
    """Format a date and time as DD-MM-YYYY hh:mm AM/PM in IST."""
    parsed = _parse_datetime(value)

    if parsed is None:
        return "—"

    if not isinstance(parsed, datetime):
        return parsed.strftime("%d-%m-%Y")

    return parsed.strftime("%d-%m-%Y %I:%M %p")
