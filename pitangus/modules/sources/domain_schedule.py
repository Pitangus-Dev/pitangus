"""When a domain's scheduled passive scan runs: a rule (daily, some weekdays or some days of the month, at a time of
day in an IANA timezone) and the next moment it fires, in UTC.

At most one run per local day: a rule has a single time of day, and `next_run` skips the local day of the last scan
(`not_on`). A wall time that doesn't exist on a given day (spring-forward gap) fires at the same offset as before
the change, i.e. later by the gap; one that happens twice (fall-back) fires the first time. The panel's preview
(`web/src/features/domains/schedule.ts`) follows the same steps.
"""

from __future__ import annotations

import re
from datetime import date, datetime, time, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pitangus.shared.i18n import msg

FREQUENCIES = ("daily", "weekly", "monthly")
MONTH_DAYS = range(1, 29)  # every month has them all
WEEKDAYS = range(1, 8)     # ISO: 1 is Monday, 7 is Sunday
TIME = re.compile(r"([01]\d|2[0-3]):([0-5]\d)")
ZONE = re.compile(r"[A-Za-z0-9_+\-]+(?:/[A-Za-z0-9_+\-]+){0,2}")
LOOKAHEAD_DAYS = 70  # a monthly rule fires within 31 days; one skipped local day on top


class ScheduleError(ValueError):
    def __init__(self, message):
        super().__init__(str(message))
        self.message = message


def zone(name) -> ZoneInfo:
    if not isinstance(name, str) or len(name) > 64 or not ZONE.fullmatch(name):
        raise ScheduleError(msg("sources.domains.schedule.invalid_timezone", zone=str(name)[:64]))
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError, OSError) as exc:
        raise ScheduleError(msg("sources.domains.schedule.invalid_timezone", zone=name)) from exc


def _days(values, allowed: range) -> list[int]:
    if not isinstance(values, list) or not values or any(type(value) is not int or value not in allowed for value in values):
        raise ScheduleError(msg("sources.domains.schedule.invalid"))
    return sorted(set(values))


def normalize(rule) -> dict:
    """The rule as stored: only the list its frequency uses, sorted and without repeats. Raises ScheduleError."""
    if not isinstance(rule, dict) or rule.get("frequency") not in FREQUENCIES:
        raise ScheduleError(msg("sources.domains.schedule.invalid"))
    if not isinstance(rule.get("time"), str) or not TIME.fullmatch(rule["time"]):
        raise ScheduleError(msg("sources.domains.schedule.invalid_time"))
    zone(rule.get("timezone"))
    frequency = rule["frequency"]
    return {"frequency": frequency,
            "weekdays": _days(rule.get("weekdays"), WEEKDAYS) if frequency == "weekly" else [],
            "month_days": _days(rule.get("month_days"), MONTH_DAYS) if frequency == "monthly" else [],
            "time": rule["time"], "timezone": rule["timezone"]}


def matches(rule: dict, day: date) -> bool:
    if rule["frequency"] == "weekly":
        return day.isoweekday() in rule["weekdays"]
    if rule["frequency"] == "monthly":
        return day.day in rule["month_days"]
    return True


def local_day(moment: datetime, rule: dict) -> date:
    return moment.astimezone(zone(rule["timezone"])).date()


def at(rule: dict, day: date) -> datetime:
    """The rule's time of day on `day`, in UTC (fold=0: before the change in a gap, the first one in an overlap)."""
    hour, minute = (int(part) for part in rule["time"].split(":"))
    return datetime.combine(day, time(hour, minute), tzinfo=zone(rule["timezone"])).astimezone(timezone.utc)


def next_run(rule: dict, after: datetime, *, not_on: date | None = None) -> datetime:
    """The first moment strictly after `after` the rule fires, skipping local days up to and including `not_on`."""
    start = local_day(after, rule)
    for offset in range(LOOKAHEAD_DAYS):
        day = start + timedelta(days=offset)
        if (not_on is not None and day <= not_on) or not matches(rule, day):
            continue
        moment = at(rule, day)
        if moment > after:
            return moment
    raise ScheduleError(msg("sources.domains.schedule.invalid"))  # unreachable with a normalized rule


def legacy(next_at: datetime | None, *, now: datetime) -> dict:
    """The rule an old weekly schedule (every seven days from its next run) becomes: that weekday and time, in UTC."""
    moment = (next_at or now).astimezone(timezone.utc)
    return {"frequency": "weekly", "weekdays": [moment.isoweekday()], "month_days": [],
            "time": f"{moment.hour:02d}:{moment.minute:02d}", "timezone": "UTC"}
