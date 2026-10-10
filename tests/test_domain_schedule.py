"""When a scheduled domain scan runs next: weekdays, days of the month, time zones and their DST changes."""

import unittest
from datetime import date, datetime, timezone

from pitangus.modules.sources.domain_schedule import ScheduleError, legacy, next_run, normalize

UTC = timezone.utc


def rule(frequency="daily", *, weekdays=(), month_days=(), time="09:00", zone="UTC"):
    return normalize({"frequency": frequency, "weekdays": list(weekdays), "month_days": list(month_days), "time": time, "timezone": zone})


def runs(schedule, start, count):
    """The next `count` runs from `start`, each one after the previous (as the scheduler moves on)."""
    moments, after = [], start
    for _ in range(count):
        after = next_run(schedule, after)
        moments.append(after)
    return moments


class NextRunTests(unittest.TestCase):
    def test_daily_runs_today_if_the_time_is_ahead_else_tomorrow(self):
        daily = rule(time="09:00", zone="America/Bogota")  # UTC-5, no DST
        self.assertEqual(next_run(daily, datetime(2026, 10, 9, 13, 59, tzinfo=UTC)), datetime(2026, 10, 9, 14, 0, tzinfo=UTC))
        self.assertEqual(next_run(daily, datetime(2026, 10, 9, 14, 0, tzinfo=UTC)), datetime(2026, 10, 10, 14, 0, tzinfo=UTC))

    def test_several_weekdays_in_order_across_the_week(self):
        schedule = rule("weekly", weekdays=[5, 1, 3], time="18:30", zone="Europe/Madrid")
        moments = runs(schedule, datetime(2026, 10, 9, 17, 0, tzinfo=UTC), 4)  # Friday 19:00 in Madrid
        self.assertEqual([moment.astimezone(UTC).strftime("%a %d %H:%M") for moment in moments],
                         ["Mon 12 16:30", "Wed 14 16:30", "Fri 16 16:30", "Mon 19 16:30"])

    def test_month_days_skip_to_the_next_month_and_february_has_them_all(self):
        schedule = rule("monthly", month_days=[28, 1, 15], time="00:00")
        moments = runs(schedule, datetime(2027, 1, 28, 0, 0, tzinfo=UTC), 4)
        self.assertEqual([moment.date() for moment in moments], [date(2027, 2, 1), date(2027, 2, 15), date(2027, 2, 28), date(2027, 3, 1)])

    def test_local_days_follow_the_zone_not_utc(self):
        # Monday 01:00 in Tokyo is still Sunday in UTC.
        schedule = rule("weekly", weekdays=[1], time="01:00", zone="Asia/Tokyo")
        moment = next_run(schedule, datetime(2026, 10, 9, 0, 0, tzinfo=UTC))
        self.assertEqual((moment, moment.isoweekday()), (datetime(2026, 10, 11, 16, 0, tzinfo=UTC), 7))

    def test_the_wall_time_holds_across_dst_changes(self):
        schedule = rule(time="09:00", zone="America/New_York")
        moments = runs(schedule, datetime(2026, 3, 7, 0, 0, tzinfo=UTC), 2)  # DST starts on Sunday 8 March
        self.assertEqual(moments, [datetime(2026, 3, 7, 14, 0, tzinfo=UTC), datetime(2026, 3, 8, 13, 0, tzinfo=UTC)])
        moments = runs(schedule, datetime(2026, 10, 31, 0, 0, tzinfo=UTC), 2)  # and ends on Sunday 1 November
        self.assertEqual(moments, [datetime(2026, 10, 31, 13, 0, tzinfo=UTC), datetime(2026, 11, 1, 14, 0, tzinfo=UTC)])

    def test_a_time_in_the_spring_gap_runs_later_by_the_gap_and_one_in_the_autumn_overlap_runs_once(self):
        gap = rule(time="02:30", zone="America/New_York")
        self.assertEqual(next_run(gap, datetime(2026, 3, 8, 0, 0, tzinfo=UTC)), datetime(2026, 3, 8, 7, 30, tzinfo=UTC))  # 03:30 EDT
        overlap = rule(time="01:30", zone="America/New_York")
        first = next_run(overlap, datetime(2026, 11, 1, 0, 0, tzinfo=UTC))
        self.assertEqual(first, datetime(2026, 11, 1, 5, 30, tzinfo=UTC))  # the first 01:30 (EDT)
        self.assertEqual(next_run(overlap, first), datetime(2026, 11, 2, 6, 30, tzinfo=UTC))  # not the second 01:30 (EST)
        madrid = rule(time="02:15", zone="Europe/Madrid")  # Europe moves on the last Sunday of March
        self.assertEqual(next_run(madrid, datetime(2026, 3, 29, 0, 0, tzinfo=UTC)), datetime(2026, 3, 29, 1, 15, tzinfo=UTC))

    def test_not_on_skips_up_to_that_local_day(self):
        daily = rule(time="23:00", zone="America/Bogota")
        after = datetime(2026, 10, 9, 15, 0, tzinfo=UTC)
        self.assertEqual(next_run(daily, after), datetime(2026, 10, 10, 4, 0, tzinfo=UTC))
        self.assertEqual(next_run(daily, after, not_on=date(2026, 10, 9)), datetime(2026, 10, 11, 4, 0, tzinfo=UTC))

    def test_rules_are_validated_and_normalized(self):
        self.assertEqual(rule("weekly", weekdays=[7, 1, 7], month_days=[3]), {"frequency": "weekly", "weekdays": [1, 7], "month_days": [],
                                                                               "time": "09:00", "timezone": "UTC", "test_users": [],
                                                                               "use_headers": False})
        users = normalize({"frequency": "daily", "time": "09:00", "timezone": "UTC", "test_users": ["a" * 24, "b" * 24, "a" * 24],
                           "use_headers": True})
        self.assertEqual((users["test_users"], users["use_headers"]), (["a" * 24, "b" * 24], True))
        for bad in ({"frequency": "yearly"}, {"frequency": "daily", "time": "09:00", "timezone": ""},
                    {"frequency": "daily", "time": "09:00", "timezone": "UTC", "test_users": ["../x"]},
                    {"frequency": "daily", "time": "09:00", "timezone": "UTC", "test_users": "a" * 24},
                    {"frequency": "daily", "time": "09:00", "timezone": "UTC", "test_users": ["a" * 24, "b" * 24, "c" * 24, "d" * 24]},
                    {"frequency": "daily", "time": "09:00", "timezone": "UTC", "use_headers": "yes"},
                    {"frequency": "daily", "time": "09:00", "timezone": "Not/AZone"}, {"frequency": "daily", "time": "9am", "timezone": "UTC"},
                    {"frequency": "monthly", "month_days": [0], "time": "09:00", "timezone": "UTC"}, None):
            with self.subTest(bad=bad), self.assertRaises(ScheduleError):
                normalize(bad)

    def test_an_old_weekly_schedule_becomes_its_weekday_and_time_in_utc(self):
        self.assertEqual(legacy(datetime(2026, 10, 14, 21, 7, tzinfo=UTC), now=datetime(2026, 10, 9, tzinfo=UTC)),
                         {"frequency": "weekly", "weekdays": [3], "month_days": [], "time": "21:07", "timezone": "UTC"})


if __name__ == "__main__":
    unittest.main()
