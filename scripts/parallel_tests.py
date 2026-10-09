"""Runs the backend tests in N workers (default: the CPUs, at most 4) and fails if any module fails.

Each worker takes the next test module from a shared queue, largest first, so they all end at about the same time
however long each module takes. Each worker has its own config folder (the master key file is created on first use);
the database is shared, and each test already isolates itself in its own schema (PITANGUS_DB_ISOLATE=data-dir).

    python scripts/parallel_tests.py [workers]
"""

from __future__ import annotations

import os
import queue
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

TESTS = Path(__file__).resolve().parent.parent / "tests"


def main() -> int:
    workers = int(sys.argv[1]) if len(sys.argv) > 1 else min(4, os.cpu_count() or 1)
    pending: queue.Queue[str] = queue.Queue()
    for path in sorted(TESTS.glob("test_*.py"), key=lambda path: path.stat().st_size, reverse=True):
        pending.put(path.stem)
    path_env = os.pathsep.join(filter(None, [str(TESTS.parent), os.environ.get("PYTHONPATH")]))
    results: list[tuple[str, int, str, float]] = []
    lock = threading.Lock()

    def work() -> None:
        with tempfile.TemporaryDirectory(prefix="pitangus-tests-") as config:
            run(config)

    def run(config: str) -> None:
        while True:
            try:
                name = pending.get_nowait()
            except queue.Empty:
                return
            began = time.monotonic()
            completed = subprocess.run([sys.executable, "-m", "unittest", name], cwd=TESTS, capture_output=True, text=True,
                                       env={**os.environ, "PITANGUS_CONFIG_DIR": config, "PYTHONPATH": path_env})
            with lock:
                results.append((name, completed.returncode, completed.stdout + completed.stderr, time.monotonic() - began))

    started = time.monotonic()
    threads = [threading.Thread(target=work) for _ in range(workers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    failed = [(name, output) for name, code, output, _ in results if code]
    ran = sum(int(line.split()[1]) for _, _, output, _ in results for line in output.splitlines() if line.startswith("Ran "))
    for name, output in failed:
        print(f"::group::{name} failed\n{output}::endgroup::" if os.environ.get("GITHUB_ACTIONS") else f"--- {name} failed ---\n{output}", flush=True)
    slowest = sorted(results, key=lambda result: result[3], reverse=True)[:3]
    print("slowest: " + ", ".join(f"{name} {seconds:.0f} s" for name, _, _, seconds in slowest), flush=True)
    print(f"{ran} tests in {len(results)} modules, {workers} workers, {time.monotonic() - started:.0f} s: "
          + (f"FAILED ({', '.join(name for name, _ in failed)})" if failed else "OK"), flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
