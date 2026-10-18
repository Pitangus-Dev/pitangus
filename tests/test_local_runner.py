"""The local runner: the engines installed next to the worker, for platforms without a Docker socket."""

import base64
import json
import os
import stat
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from pitangus.modules.scanning import engines

# A stand-in engine: prints what it received (arguments, part of its environment, what it can read).
FAKE = """#!/bin/sh
printf '{"args": "%s", "home": "%s", "db": "%s", "key": "%s", "cache": "%s"}\\n' "$*" "$HOME" "$PITANGUS_DATABASE_URL" "$PITANGUS_MASTER_KEY" "$OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY"
cat "$2/app.py" >&2
"""
# Writes its own PID and its child's, so the test checks those processes and nothing else on the machine.
SLEEPER = """#!/bin/sh
sleep 30 &
echo "$$ $!" > '{pids}'
wait
"""


def alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except OSError:  # gone, or reused by another user's process
        return False
    return True


class LocalRunnerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        root = Path(self.directory.name)
        self.bin, self.snapshot, self.cache = root / "bin", root / "snapshot", root / "cache"
        for folder in (self.bin, self.snapshot, self.cache):
            folder.mkdir()
        (self.snapshot / "app.py").write_text("print('hi')\n")
        path = f"{self.bin}:/usr/bin:/bin"  # only the stand-ins, whatever the machine has installed
        environment = patch.dict(os.environ, {"PATH": path, "PITANGUS_ENGINE_RUNNER": "local",
                                              "PITANGUS_MASTER_KEY": base64.b64encode(b"not-a-real-key-just-a-test-1234").decode()})
        environment.start()
        self.addCleanup(environment.stop)

    def install(self, name: str, script: str) -> None:
        path = self.bin / name
        path.write_text(script)
        path.chmod(path.stat().st_mode | stat.S_IXUSR)

    def test_container_paths_become_real_folders_and_back(self):
        self.install("osv-scanner", FAKE)
        completed = engines._run("osv-scanner", ["scan", "/src", "--cache", "/cache/db"], self.snapshot,
                                 env={"OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY": "/cache"},
                                 mounts=["-v", f"{engines.host_path(self.cache)}:/cache"])
        seen = json.loads(completed.stdout)
        self.assertEqual(seen["args"], "scan /src --cache /cache/db")  # the parsers keep seeing container paths
        self.assertEqual(seen["cache"], "/cache")
        self.assertEqual(completed.stderr, "print('hi')\n")  # but the engine read the real snapshot
        self.assertEqual((seen["db"], seen["key"]), ("", ""))  # never the worker's settings
        self.assertNotEqual(seen["home"], os.environ.get("HOME"))

    def test_readiness_follows_what_is_installed(self):
        self.assertFalse(engines.engine_ready("betterleaks"))
        self.assertIn("Betterleaks", str(engines.unavailable("betterleaks", "docker message")))
        self.install("betterleaks", FAKE)
        self.assertTrue(engines.engine_ready("betterleaks"))
        self.assertIsNone(engines.unavailable("betterleaks", "docker message"))
        self.assertTrue(engines.engines_available())

    def test_a_timeout_kills_the_engine_and_what_it_started(self):
        pids = Path(self.directory.name) / "pids"
        self.install("zizmor", SLEEPER.format(pids=pids))
        started = time.monotonic()
        with self.assertRaises(subprocess.TimeoutExpired):
            engines._run("zizmor", ["/src"], self.snapshot, timeout=1)
        self.assertLess(time.monotonic() - started, 10)
        started_pids = [int(pid) for pid in pids.read_text().split()]
        self.assertEqual(len(started_pids), 2)
        # The orphaned child is reaped by init, not by us: give it a moment before calling it a leftover.
        deadline = time.monotonic() + 5
        while (leftovers := [pid for pid in started_pids if alive(pid)]) and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertEqual(leftovers, [])

    def test_opengrep_rule_ids_are_the_same_whatever_the_rules_folder(self):
        self.assertEqual(engines._rule_id("rules.appsec.py.eval-exec-non-literal"), "appsec.py.eval-exec-non-literal")
        self.assertEqual(engines._rule_id("data.work.scan-2l5.opengrep-rules.appsec.py.eval-exec-non-literal"),
                         "appsec.py.eval-exec-non-literal")

    def test_arguments_reach_the_engine_untouched_and_no_core_dumps(self):
        self.install("betterleaks", '#!/bin/sh\nprintf "%s|" "$@"; ulimit -c\n')
        tricky = ["dir", "/src", "--report-path", "a b; echo pwned", "$(id)", "`id`", "*"]
        completed = engines._run("betterleaks", tricky, self.snapshot)
        self.assertEqual(completed.stdout.strip(), "dir|/src|--report-path|a b; echo pwned|$(id)|`id`|*|0")



PREFIX = ["/usr/bin/unshare", "--user", "--map-current-user", "--net", "--"]


class NetworkIsolationTests(unittest.TestCase):
    """Local engines that need no network get an empty network namespace where the platform allows it."""

    def setUp(self):
        engines._netns_state.clear()
        self.addCleanup(engines._netns_state.clear)

    def launched(self, network: bool) -> list[str]:
        seen = {}

        class Process:
            pid, returncode = 1, 0

            def __init__(self, command, **_):
                seen["command"] = command

            def communicate(self, timeout=None):
                return "", ""
        with patch.dict(os.environ, {"PITANGUS_ENGINE_RUNNER": "local"}), \
                patch.object(engines.shutil, "which", return_value="/usr/local/bin/betterleaks"), \
                patch.object(engines, "network_isolation", return_value=PREFIX), \
                patch.object(engines.subprocess, "Popen", Process):
            engines._run("betterleaks", ["dir", "/src"], Path("/tmp"), network=network)
        return seen["command"]

    def test_only_engines_without_network_are_isolated(self):
        self.assertEqual(self.launched(network=False)[:len(PREFIX)], PREFIX)
        self.assertEqual(self.launched(network=True)[0], "/bin/sh")

    def test_the_probe_falls_back_and_is_asked_once(self):
        answers = [subprocess.CompletedProcess([], 1), subprocess.CompletedProcess([], 0)]
        with patch.object(engines.shutil, "which", return_value="/usr/bin/unshare"), \
                patch.object(engines.subprocess, "run", side_effect=answers) as run:
            self.assertEqual(engines.network_isolation(), ["/usr/bin/unshare", "--user", "--map-root-user", "--net", "--"])
            engines.network_isolation()
        self.assertEqual(run.call_count, 2)

    def test_without_unshare_engines_run_as_before_and_it_is_logged(self):
        with patch.object(engines.shutil, "which", return_value=None), self.assertLogs("pitangus.engines", "WARNING") as logs:
            self.assertEqual(engines.network_isolation(), [])
        self.assertIn("local_engines_share_the_network", logs.output[0])

    def test_an_isolated_engine_cannot_reach_the_network(self):
        if not engines.network_isolation():
            self.skipTest("this platform doesn't allow user and network namespaces")
        probe = "import socket\ntry:\n    socket.create_connection(('1.1.1.1', 53), 3)\nexcept OSError as exc:\n    print(exc.errno)\nelse:\n    print('reached')\n"
        completed = subprocess.run([*engines.network_isolation(), "python3", "-c", probe], capture_output=True, text=True, timeout=30)
        self.assertNotEqual(completed.stdout.strip(), "reached")

if __name__ == "__main__":
    unittest.main()
