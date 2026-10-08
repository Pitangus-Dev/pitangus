"""What a test that empties the environment must keep: the test database and the temporary configuration folder."""

import os

KEEP = ("PITANGUS_DATABASE_URL", "PITANGUS_DB_ISOLATE", "PITANGUS_CONFIG_DIR")


def base(**extra) -> dict:
    return {**{name: os.environ[name] for name in KEEP if name in os.environ}, **extra}


def docker_runner(case) -> None:
    """Pins the Docker engine runner for a test. With `auto`, the first check (often a patched one) would choose the
    runner for every test after it."""
    from unittest.mock import patch
    pinned = patch.dict(os.environ, {"PITANGUS_ENGINE_RUNNER": "docker"})
    pinned.start()
    case.addCleanup(pinned.stop)
