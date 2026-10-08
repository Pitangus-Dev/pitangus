"""The app as an ASGI object, for platforms that import it instead of running `pitangus serve` (Vercel's Python
runtime, or any ASGI server: `uvicorn pitangus.app.asgi:app`).

Everything comes from the environment: PITANGUS_DATABASE_URL, PITANGUS_MASTER_KEY, PITANGUS_PUBLIC_URL and
PITANGUS_ALLOWED_ORIGINS at least. This process never runs scans (a worker elsewhere does) and never starts periodic
tasks. The data folder only holds caches that rebuild themselves (PITANGUS_DATA_DIR, or the system's temporary folder).
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from pitangus.app.api import create_app
from pitangus.app.api.server import build_state, transport_check
from pitangus.shared import settings
from pitangus.shared.i18n import t, text

PORT = 443  # only used when PITANGUS_PUBLIC_URL is missing, which the checks below refuse


def _build():
    problems = [text(problem) for problem in settings.problems()]
    if not settings.is_set("PITANGUS_PUBLIC_URL"):
        problems.append(t("cli.settings.missing", name="PITANGUS_PUBLIC_URL"))
    insecure = transport_check(PORT)
    if insecure:
        problems.append(insecure)
    if problems:
        raise RuntimeError("\n".join([t("cli.settings.header"), *problems]))
    data_dir = Path(settings.text("PITANGUS_DATA_DIR") or Path(tempfile.gettempdir()) / "pitangus")
    data_dir.mkdir(parents=True, exist_ok=True)
    state = build_state(data_dir, watch_pull_requests=False, worker=False)
    code = state.auth.setup_code()
    if code:
        print(f"{t('cli.server.setup_code')}: {code}", flush=True)  # in the platform's logs, like on a server's console
    return create_app(data_dir, port=PORT, state=state)


app = _build()
