"""What a test that empties the environment must keep: the test database and the temporary configuration folder."""

import os

KEEP = ("PITANGUS_DATABASE_URL", "PITANGUS_DB_ISOLATE", "PITANGUS_CONFIG_DIR")


def base(**extra) -> dict:
    return {**{name: os.environ[name] for name in KEEP if name in os.environ}, **extra}


def stop_worker(case, jobs) -> None:
    """Stops a ScanJobs' worker threads and fails if they don't end. One left running would claim the work of the tests
    after it and call their patched functions: its image lane pulling inside another test's `pull_image` patch."""
    case.assertTrue(jobs.stop(timeout=10), "the worker's threads outlived the test")


def docker_runner(case) -> None:
    """Pins the Docker engine runner for a test. With `auto`, the first check (often a patched one) would choose the
    runner for every test after it."""
    from unittest.mock import patch
    pinned = patch.dict(os.environ, {"PITANGUS_ENGINE_RUNNER": "docker"})
    pinned.start()
    case.addCleanup(pinned.stop)
    # Every engine image is on the server unless a test says otherwise (a missing one is declared not run).
    from pitangus.modules.scanning import engines
    present = patch.object(engines, "image_available", return_value=True)
    present.start()
    case.addCleanup(present.stop)
    # A web scan's other tools (katana, nuclei, testssl.sh, httpx) ask Docker for their images: absent unless a test
    # hands them to `scan_domain` itself.
    from pitangus.modules.scanning import web_tools
    from pitangus.shared.i18n import msg
    absent = patch.object(web_tools, "readiness", return_value={key: msg("scanning.web.tools.image_missing", tool=key) for key in web_tools.TOOLS})
    absent.start()
    case.addCleanup(absent.stop)
    from pitangus.modules.scanning import web_versions
    lookup = patch.object(web_versions, "readiness", return_value=msg("scanning.web.tools.image_missing", tool="OSV-Scanner"))
    lookup.start()
    case.addCleanup(lookup.stop)


def read_log(engine: str, root, paths=None) -> str:
    """What a secret engine logs for each file it reads (secret_coverage), for every file under `root` or for `paths`:
    a fake engine that read the snapshot says so, as the real one does."""
    from pathlib import Path
    root = Path(root)
    if paths is None:
        paths = sorted(path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file()) if root.is_dir() else []
    if engine == "betterleaks":
        return "".join(f'6:01PM TRC scanning path path="/src/{path}"\n' for path in paths)
    return "".join(f'2026-10-14T18:04:16Z\tDEBUG\t[secret] Using streaming scanner\tfile_path="{path}"\n' for path in paths)
