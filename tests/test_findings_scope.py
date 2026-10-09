"""Findings of several assets at once: an organization, a chosen set or everything, by tab, in one view."""

import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from pitangus.modules.compliance import provenance
from pitangus.modules.findings import fix_guide, registry, triage
from pitangus.modules.runs.store import save_repository_scan
from test_auth import HttpCase
from test_compliance import _image, _login
from test_dashboard import _finding, _scan

A, B, C, D = "a" * 64, "b" * 64, "c" * 64, "d" * 64
USER = {"username": "ana", "role": "member"}
LABEL = {"org.opencontainers.image.source": "https://github.com/org/api"}


class ScopedFindingsTests(HttpCase):
    def setUp(self):
        super().setUp()
        stamp = datetime.now(timezone.utc).isoformat()
        urgent = {**_finding(A, "critical", package="lodash"), "priority": {"action": "act", "factors": []}}
        save_repository_scan(self.data_dir, _scan("org/api", [urgent, _finding(B, "high")], stamp), created_at=stamp)
        # The same fingerprint in another repository is another finding.
        save_repository_scan(self.data_dir, _scan("org/web", [_finding(A, "medium")], stamp), created_at=stamp)
        save_repository_scan(self.data_dir, _scan("other/lib", [_finding(C, "low")], stamp), created_at=stamp)
        save_repository_scan(self.data_dir, {**_image("ghcr.io/org/api", stamp, labels=LABEL), "findings": [_finding(D, "high", package="openssl")]},
                             created_at=stamp)

    def view(self, status="open", limit=registry.SCOPE_FINDINGS_MAX, **scope):
        return registry.scoped_view(self.data_dir, provenance.scope(self.data_dir, **scope), status=status, limit=limit)

    def test_an_organization_brings_its_repositories_and_their_images(self):
        result = self.view(account="org")
        self.assertEqual(result["type"], "asset_scope")
        self.assertEqual(sorted((item["asset"]["name"], item["fingerprint"][0]) for item in result["findings"]),
                         [("ghcr.io/org/api", "d"), ("org/api", "a"), ("org/api", "b"), ("org/web", "a")])
        self.assertEqual({item["asset"]["kind"] for item in result["findings"]}, {"repository", "image"})
        # Each asset with its pending work, the most critical first; the counts add up.
        self.assertEqual([(row["name"], row["open"], row["critical"], row["shown"]) for row in result["by_asset"]][0], ("org/api", 2, 1, 2))
        self.assertEqual({row["name"] for row in result["by_asset"]}, {"org/api", "org/web", "ghcr.io/org/api"})
        self.assertEqual((result["summary"]["lifecycle"]["open"], result["summary"]["lifecycle"]["by_severity"]["critical"]), (4, 1))
        kpis = result["summary"]["kpis"]
        self.assertEqual((kpis["active"], kpis["act"], kpis["critical"], kpis["high"], kpis["fixable"]), (4, 1, 1, 2, 4))
        self.assertEqual((result["total"], result["truncated"]), (4, False))
        # The most urgent first: the critical one to act on now.
        self.assertEqual((result["findings"][0]["asset"]["name"], result["findings"][0]["fingerprint"]), ("org/api", A))
        self.assertEqual({row["key"] for row in self.view(account="org", include_images=False)["by_asset"]}, {"github:org/api", "github:org/web"})
        self.assertEqual(len(self.view()["by_asset"]), 4)
        self.assertEqual({row["name"] for row in self.view(assets=["github:org/api"])["by_asset"]}, {"org/api", "ghcr.io/org/api"})

    def test_triage_stays_on_its_asset_and_tabs_follow_it(self):
        api = registry.view(self.data_dir, "github:org/api", status="all")
        triage.decide(self.data_dir, api, [A], "false_positive", reason="Not reachable from our code", user=USER)
        triage.decide(self.data_dir, api, [B], "fixed", reason="Upgraded by hand in production", user=USER)
        result = self.view(account="org", include_images=False)
        by = {(item["asset"]["name"], item["fingerprint"]): item for item in result["findings"]}
        # Dismissed stays in the open tab (the table filters it); the same fingerprint elsewhere is untouched.
        self.assertEqual((by[("org/api", A)]["triage"]["status"], by[("org/web", A)]["triage"]["status"]), ("false_positive", "open"))
        self.assertNotIn(("org/api", B), by)
        self.assertEqual((result["summary"]["kpis"]["active"], result["summary"]["kpis"]["dismissed"]), (1, 1))
        lifecycle = result["summary"]["lifecycle"]
        self.assertEqual((lifecycle["open"], lifecycle["suppressed"], lifecycle["fixed"]), (1, 1, 1))
        fixed = self.view("fixed", account="org", include_images=False)["findings"]
        self.assertEqual([(item["asset"]["name"], item["fingerprint"]) for item in fixed], [("org/api", B)])
        self.assertEqual(len(self.view("all", account="org", include_images=False)["findings"]), 3)
        self.assertEqual(self.view("excluded", account="org")["findings"], [])

    def test_past_the_cap_only_the_most_urgent_come_and_it_says_so(self):
        result = self.view(limit=2)
        self.assertEqual((len(result["findings"]), result["total"], result["truncated"]), (2, 5, True))
        self.assertEqual(result["findings"][0]["fingerprint"], A)
        # The counts still cover everything.
        self.assertEqual((result["summary"]["kpis"]["active"], sum(row["shown"] for row in result["by_asset"])), (5, 5))

    def test_only_the_findings_served_get_their_fix_guides(self):
        with patch.object(fix_guide, "guide", wraps=fix_guide.guide) as guide:
            result = self.view(limit=2)
        self.assertEqual(guide.call_count, 2)
        self.assertTrue(all(item.get("fix") for item in result["findings"]))
        # The fix that closes a package's advisories still looks at all of them, served or not.
        self.assertEqual(result["findings"][0]["fix"], self.view()["findings"][0]["fix"])

    def test_the_tiles_count_the_same_pending_work_in_one_asset_and_in_a_scope(self):
        stamp = datetime.now(timezone.utc).isoformat()
        save_repository_scan(self.data_dir, _scan("org/api", [_finding(A, "critical", package="lodash")], stamp), created_at=stamp)  # B fixed by the scan
        api = registry.view(self.data_dir, "github:org/api", status="all")
        triage.decide(self.data_dir, api, [A], "in_progress", user=USER)
        one = registry.view(self.data_dir, "github:org/api", status="all")["summary"]["kpis"]
        scope = self.view("all", assets=["github:org/api"], include_images=False)["summary"]["kpis"]
        self.assertEqual(one, scope)
        # Fixed, by a scan or by hand, isn't pending work; in progress still is.
        self.assertEqual((one["active"], one["dismissed"], one["critical"], one["high"]), (1, 1, 1, 0))

    def test_through_the_api(self):
        member = _login(self, "miembro")
        cookie = {"Cookie": member, "Accept-Language": "en"}
        self.assertEqual(self.call("GET", "/api/findings/scope")[0], 401)
        status, body, _ = self.call("GET", "/api/findings/scope?account=org", headers=cookie)
        self.assertEqual((status, body["total"], body["truncated"], len(body["by_asset"])), (200, 4, False, 3))
        self.assertTrue(all(isinstance(item["title"], str) for item in body["findings"]))  # rendered for the reader
        status, body, _ = self.call("GET", "/api/findings/scope?assets=github:org/web&assets=github:other/lib&status=all", headers=cookie)
        self.assertEqual(sorted(item["asset"]["name"] for item in body["findings"]), ["org/web", "other/lib"])
        self.assertEqual(self.call("GET", "/api/findings/scope?account=nobody", headers=cookie)[1]["by_asset"], [])
        self.assertEqual(self.call("GET", "/api/findings/scope?account=org&include_images=false", headers=cookie)[1]["total"], 3)
        for bad in ("account=org&assets=github:org/api", "status=nope", "account=" + "a" * 101, "assets=" + "a" * 201):
            self.assertEqual(self.call("GET", f"/api/findings/scope?{bad}", headers=cookie)[0], 400, bad)

        # Triage across assets goes per asset (its state as run_id): one asset's decision leaves the other alone.
        status, _, _ = self.post("/api/findings/triage", "triage", {"run_id": "asset:github:org/web", "fingerprints": [A], "status": "in_progress"}, member)
        self.assertEqual(status, 200)
        _, body, _ = self.call("GET", "/api/findings/scope?account=org", headers=cookie)
        states = {item["asset"]["name"]: item["triage"]["status"] for item in body["findings"] if item["fingerprint"] == A}
        self.assertEqual(states, {"org/api": "open", "org/web": "in_progress"})

    def test_triage_across_assets_in_one_request(self):
        member = _login(self, "miembro")
        triage_ = lambda body: self.post("/api/findings/triage", "triage", body, member)[:2]  # noqa: E731
        both = [{"run_id": "asset:github:org/api", "fingerprints": [A, B]}, {"run_id": "asset:github:org/web", "fingerprints": [A]}]
        status, body = triage_({"selections": both, "status": "in_progress"})
        self.assertEqual((status, body), (200, {"results": [{"run_id": "asset:github:org/api"}, {"run_id": "asset:github:org/web"}]}))
        result = self.view(account="org", include_images=False)
        self.assertEqual({item["triage"]["status"] for item in result["findings"]}, {"in_progress"})

        # Each asset lands on its own: the one that fails says why, the rest stays applied.
        status, body = triage_({"selections": [{"run_id": "asset:github:org/web", "fingerprints": [A]},
                                               {"run_id": "asset:github:org/api", "fingerprints": [C]}], "status": "open"})
        self.assertEqual(status, 200)
        self.assertEqual([("error" in item, item["run_id"]) for item in body["results"]], [(False, "asset:github:org/web"), (True, "asset:github:org/api")])
        self.assertTrue(body["results"][1]["error"])
        states = {item["asset"]["name"]: item["triage"]["status"] for item in self.view(account="org", include_images=False)["findings"] if item["fingerprint"] == A}
        self.assertEqual(states, {"org/api": "in_progress", "org/web": "open"})
        # None lands: it fails as one would, with the same status.
        self.assertEqual(triage_({"selections": [{"run_id": "0" * 32, "fingerprints": [A]}], "status": "open"})[0], 404)
        self.assertEqual(triage_({"selections": both, "status": "accepted", "reason": "Behind the VPN for now"})[0], 403)
        self.assertEqual(triage_({"selections": both, "status": "fixed"})[0], 400)  # no reason

        too_many = [{"run_id": f"asset:github:org/r{index}", "fingerprints": [A] * 2} for index in range(triage.MAX_BATCH // 2 + 1)]
        for bad in ({"selections": both, "run_id": "asset:github:org/api", "status": "open"},
                    {"selections": both, "fingerprints": [A], "status": "open"},
                    {"status": "open"}, {"selections": [], "status": "open"},
                    {"selections": [both[0], both[0]], "status": "open"},
                    {"selections": too_many, "status": "open"},
                    {"selections": [{"run_id": "asset:github:org/api"}], "status": "open"}):
            self.assertEqual(triage_(bad)[0], 400, bad)
        # One run, as before: its counts.
        status, body = triage_({"run_id": "asset:github:org/api", "fingerprints": [A], "status": "open"})
        self.assertEqual((status, set(body)), (200, {"summary"}))

    def test_a_single_run_carries_its_tiles(self):
        member = _login(self, "miembro")
        run_id = registry.load(self.data_dir, "github:org/api")["findings"][A]["last_run"]
        status, body, _ = self.call("GET", f"/api/runs/{run_id}", headers={"Cookie": member})
        self.assertEqual((status, body["summary"]["kpis"]["active"], body["summary"]["kpis"]["act"]), (200, 2, 1))


if __name__ == "__main__":
    unittest.main()
