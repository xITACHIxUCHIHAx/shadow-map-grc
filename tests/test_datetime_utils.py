from datetime import date, datetime, timezone

from grc.datetime_utils import (
    format_date,
    format_time,
    format_datetime,
)


def test_format_datetime_converts_utc_to_ist():
    value = datetime(2026, 11, 15, 14, 43, tzinfo=timezone.utc)
    assert format_datetime(value) == "15-11-2026 08:13 PM"


def test_format_date_uses_day_month_year():
    assert format_date(date(2026, 11, 25)) == "25-11-2026"


def test_format_time_uses_twelve_hour_clock():
    value = datetime(2026, 11, 15, 14, 43, tzinfo=timezone.utc)
    assert format_time(value) == "08:13 PM"


def test_format_datetime_accepts_utc_iso_string():
    assert format_datetime("2026-11-15T14:43:00+00:00") == (
        "15-11-2026 08:13 PM"
    )


def test_format_datetime_accepts_z_suffix():
    assert format_datetime("2026-11-15T14:43:00Z") == (
        "15-11-2026 08:13 PM"
    )


def test_format_datetime_accepts_epoch_seconds():
    value = datetime(2026, 11, 15, 14, 43, tzinfo=timezone.utc).timestamp()
    assert format_datetime(value) == "15-11-2026 08:13 PM"


def test_date_only_datetime_output():
    assert format_datetime("2026-11-25") == "25-11-2026"


def test_invalid_values_return_dash():
    assert format_datetime("not-a-date") == "—"
    assert format_date(None) == "—"
    assert format_time("") == "—"
