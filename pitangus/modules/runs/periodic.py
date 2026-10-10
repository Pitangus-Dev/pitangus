"""Periodic tasks as rounds that anyone can trigger.

With PITANGUS_PERIODIC=leader (the default) the leader worker runs them on its own clock (threads started by
`pitangus.app.worker.start_periodic`). With `external`, nothing runs on its own: a scheduler calls `pitangus periodic`
(cron, a Kubernetes CronJob, the platform's scheduler) or `GET /api/cron` with the cron token (Vercel Cron). A round
runs what is due. What needs the engines or takes long (NVD and the advisory watch) is queued for a worker instead of
running inside the API.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from time import monotonic
from typing import Callable

from pitangus.modules.sources.domains import RECHECK_SECONDS as DOMAIN_RECHECK_SECONDS
from pitangus.shared import documents, settings
from pitangus.shared import log as logging_setup

_log = logging_setup.get("periodic")
STATE = "periodic"
NVD_BUDGET = 600  # seconds of NVD sync per round: a worker job, never a request
NVD_EVERY = 900   # longer than the budget: rounds never pile up behind each other
DOMAIN_SCAN_SECONDS = 300  # how often due scheduled web scans are looked for (a rule has a time of day)


@dataclass(frozen=True)
class Task:
    every: Callable[[], int]      # seconds between rounds; 0 means every time it's called, negative means off
    on_worker: bool                # needs the engines or takes long: an API queues it
    run: Callable[[Path, object], object]


def _outbox(data_dir: Path, jobs) -> object:
    from pitangus.modules.integrations import notifications
    from pitangus.modules.runs import jira_sync
    # Each queue on its own: a channel failing doesn't hold Jira's back, nor the other way round.
    sent, failure = 0, None
    for drain in (notifications.drain, jira_sync.drain):
        try:
            sent += drain(data_dir)
        except Exception as exc:  # noqa: BLE001 — re-raised once both queues had their turn
            failure = exc
    if failure is not None:
        raise failure
    return sent


def _pull_requests(data_dir: Path, jobs) -> object:
    from pitangus.modules.integrations.installations import github_installations
    from pitangus.modules.pullrequests.watch import Watcher
    return Watcher(data_dir, jobs, lambda: github_installations(data_dir)).poll()


def _nvd(data_dir: Path, jobs) -> object:
    """Syncs for up to NVD_BUDGET seconds. NVD failing or throttling (it answers 403/503 under load) ends the round
    quietly: the sync is resumable and the next round goes on from where this one stopped."""
    import time
    from urllib.error import URLError
    from sqlalchemy.exc import SQLAlchemyError
    from pitangus.modules.intel import cve_db
    from pitangus.modules.intel.advisories import load_feeds
    started, steps = monotonic(), 0
    try:
        cve_db.load_signals(data_dir, load_feeds(data_dir))
        while monotonic() - started < NVD_BUDGET and cve_db.sync_step(data_dir) != "idle":
            steps += 1
            if monotonic() - started + cve_db.pause() < NVD_BUDGET:
                time.sleep(cve_db.pause())
    except (URLError, TimeoutError, OSError, ValueError, SQLAlchemyError) as error:  # HTTPError is a URLError
        _log.warning("cve_sync_failed", extra={"reason": type(error).__name__})
    return steps


def _advisories(data_dir: Path, jobs) -> object:
    from pitangus.modules.runs import advisory_watch
    return advisory_watch.check(data_dir)


def _domains(data_dir: Path, jobs) -> object:
    """Looks up the TXT proof of every verified domain again (a few DNS queries: it runs wherever the round runs)."""
    from pitangus.modules.sources import domains
    return domains.recheck(data_dir)


def _joined(notes: list):
    """Whole sentences, one after another (each is a message of its own)."""
    from pitangus.shared.i18n import msg
    if not notes:
        return None
    return notes[0] if len(notes) == 1 else msg("sources.domains.schedule.notes", first=notes[0], rest=_joined(notes[1:]))


def _scheduled_options(data_dir: Path, record: dict) -> tuple[dict, list, list[str]]:
    """What the scheduled scan of `record` asks for, checked now: the saved scope, the test users chosen with the
    schedule that still exist and sign in inside that scope, and the saved headers if it sends them and some are
    left. Whatever it leaves out comes back as notes, with the ids of users deleted since."""
    from pitangus.modules.sources import domain_headers, domain_schedule, domain_scope, domains, test_users
    from pitangus.modules.sources.domains import DomainError
    from pitangus.shared.i18n import msg
    access = domain_schedule.access(record["schedule"])
    options: dict = {"mode": "web", "use_scope": True}
    notes: list = []
    try:
        scope = domains.scan_scope(record, domain_scope.saved_hosts(data_dir, record))
    except DomainError:
        scope = {"hosts": [record["host"]], "wildcards": []}  # the worker refuses it again, with the reason
    usable = test_users.still_usable(data_dir, record, access["test_users"], scope)
    if usable["kept"]:
        options["test_users"] = usable["kept"]
    if usable["gone"]:
        notes.append(msg("sources.domains.schedule.users_gone", count=len(usable["gone"])))
    if usable["outside"]:
        notes.append(msg("sources.domains.schedule.users_outside", count=len(usable["outside"]), names=", ".join(usable["outside"])))
    if access["use_headers"]:
        if domain_headers.count(record["id"]):
            options["use_headers"] = True
        else:
            notes.append(msg("sources.domains.schedule.headers_gone"))
    return options, notes, usable["gone"]


def _domain_scans(data_dir: Path, jobs, *, now: datetime | None = None) -> object:
    """Queues the scheduled passive web scan of the most overdue domain (one: web scans run one at a time). Locking
    the domain's row, queuing the scan and moving its schedule on are one transaction: a crash or a second round can
    neither queue a slot twice nor lose it. A domain whose proof lapsed is skipped with the reason and stays due;
    another web scan in progress leaves it for the next round; a domain already scanned that local day (by hand)
    moves on to its next run, so it is scanned at most once a day. Scheduled scans crawl the domain's own host
    and the hosts saved in its scope (while its DNS proof covers them), signed in as the test users chosen with the
    schedule and with its saved headers if it asked for them; what no longer fits is left out, with a note."""
    from pitangus.modules.runs.jobs import BusyError
    from pitangus.modules.runs.store import find_runs
    from pitangus.modules.sources import domain_schedule, domains
    from pitangus.shared import db
    from pitangus.shared.i18n import msg
    now = now or datetime.now(timezone.utc)
    with db.transaction(data_dir):
        for record in domains.due_scans(data_dir, now=now, lock=True):
            if not record["verified"]:
                domains.schedule_skipped(data_dir, record["id"], msg("sources.domains.schedule.lapsed"), now=now)
                _log.warning("scheduled_scan_skipped", extra={"reason": f"{record['host']}: proof lapsed"})
                continue
            today = domain_schedule.local_day(now, record["schedule"])
            last = find_runs(data_dir, types=["dast_scan"], assets=[record["key"]], limit=1)
            if last and domain_schedule.local_day(datetime.fromisoformat(last[0]["created_at"]), record["schedule"]) == today:
                domains.schedule_moved(data_dir, record["id"], msg("sources.domains.schedule.already_today"),
                                       after=now, not_on=today, now=now)
                continue
            options, notes, gone = _scheduled_options(data_dir, record)
            try:
                queued = jobs.enqueue_dast_scan(domain=record, requested_by="schedule", trigger={"kind": "schedule"},
                                                options=options)
            except BusyError:
                domains.schedule_skipped(data_dir, record["id"], msg("sources.domains.schedule.busy"), now=now)
                return {"queued": None, "waiting": record["host"]}
            domains.schedule_queued(data_dir, record["id"], queued["id"], now=now, note=_joined(notes), gone_users=gone)
            if notes:
                _log.warning("scheduled_scan_reduced", extra={"reason": f"{record['host']}: {len(gone)} test users gone, "
                                                                        f"{len(options.get('test_users', []))} kept"})
            return {"queued": queued["id"], "host": record["host"]}
    return {"queued": None}


TASKS: dict[str, Task] = {
    "outbox": Task(lambda: 0, False, _outbox),
    "pull_requests": Task(lambda: settings.integer("PITANGUS_PR_POLL_SECONDS"), False, _pull_requests),
    "nvd": Task(lambda: NVD_EVERY if settings.flag("PITANGUS_CVE_SYNC") else -1, True, _nvd),
    "advisories": Task(lambda: 3600 * settings.integer("PITANGUS_ADVISORY_WATCH_HOURS") or -1, True, _advisories),
    "domains": Task(lambda: DOMAIN_RECHECK_SECONDS, False, _domains),
    "domain_scans": Task(lambda: DOMAIN_SCAN_SECONDS if settings.flag("PITANGUS_DAST_ENABLED") else -1, False, _domain_scans),
}


def external() -> bool:
    return settings.text("PITANGUS_PERIODIC") == "external"


def _claim(data_dir: Path, names: list[str], now: datetime) -> list[str]:
    """The due tasks among `names`, marked as started in the same transaction: two schedulers firing at once never run a
    task twice."""
    claimed = []
    with documents.edit(data_dir, STATE, {}) as state:
        for name in names:
            every = TASKS[name].every()
            last = (state.get(name) or {}).get("started_at")
            if every < 0:
                continue
            if last and every and now - datetime.fromisoformat(last) < timedelta(seconds=every):
                continue
            state[name] = {**(state.get(name) or {}), "started_at": now.isoformat()}
            claimed.append(name)
    return claimed


def run_round(data_dir: Path, jobs, *, here_only: bool, only: list[str] | None = None,
              now: datetime | None = None) -> dict:
    """One round. `here_only` (an API): tasks that belong on a worker are queued, not run. Returns what happened."""
    names = [name for name in (only or TASKS) if name in TASKS]
    outcome: dict[str, list] = {"ran": [], "queued": [], "failed": []}
    for name in _claim(data_dir, names, now or datetime.now(timezone.utc)):
        if here_only and TASKS[name].on_worker:
            jobs.enqueue_periodic(name)
            outcome["queued"].append(name)
            continue
        try:
            TASKS[name].run(data_dir, jobs)
            outcome["ran"].append(name)
        except Exception:  # noqa: BLE001 — one task failing doesn't stop the others
            _log.exception("periodic_task_failed", extra={"reason": name})
            outcome["failed"].append(name)
    return outcome
