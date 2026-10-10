"""The passive web scan's other tools (katana, nuclei, testssl.sh, httpx): what each container is told, what it may
reach, how its output becomes findings, the templates nuclei may run, and one finding per problem across tools.

Parser fixtures are real outputs, cut down and scrubbed: pitangus.dev (the owner's verified domain, scanned
passively on 2026-10-10) and edge.pitangus.test, a throwaway nginx on a private address with a self-signed
certificate, no security headers, a session cookie without flags and an exposed `.git/config`."""

import io
import json
import re
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

import testenv
from pitangus.modules.scanning import engines, nuclei_templates, web, web_merge, web_tools
from pitangus.shared.i18n import text

OUTPUTS = Path(__file__).resolve().parent / "engine-outputs"
HOST, EDGE = "pitangus.dev", "edge.pitangus.test"
PINS = {HOST: "172.67.153.40"}


def fixture(name: str) -> str:
    return (OUTPUTS / name).read_text(encoding="utf-8")


def template(**overrides) -> dict:
    document = {"id": "sample", "info": {"name": "Sample", "severity": "low", "tags": "exposure,config"},
                "http": [{"method": "GET", "path": ["{{BaseURL}}/.git/config"], "matchers": [{"type": "status", "status": [200]}]}]}
    document.update(overrides)
    return document


class TemplateFilterTests(unittest.TestCase):
    def test_a_detection_template_is_kept(self):
        self.assertTrue(nuclei_templates.allowed("http/exposures/configs/sample.yaml", template()))
        self.assertTrue(nuclei_templates.allowed("ssl/sample.yaml", {"id": "tls", "info": {"name": "TLS", "severity": "info"},
                                                                     "ssl": [{"address": "{{Host}}:{{Port}}"}]}))

    def test_every_attack_tag_drops_the_template(self):
        for tag in sorted(nuclei_templates.DENY_TAGS):
            with self.subTest(tag=tag):
                self.assertFalse(nuclei_templates.allowed("http/exposures/sample.yaml",
                                                          template(info={"name": "x", "severity": "high", "tags": f"exposure,{tag}"})))
        for tag in ("intrusive", "dos", "fuzz", "bruteforce", "sqli", "rce", "lfi", "xss", "ssrf", "oast", "default-login", "headless"):
            self.assertIn(tag, nuclei_templates.DENY_TAGS)

    def test_requests_that_write_fuzz_or_call_out_are_dropped(self):
        request = {"method": "GET", "path": ["{{BaseURL}}/"]}
        cases = {
            "post": {**request, "method": "POST"},
            "body": {**request, "body": "a=1"},
            "fuzzing": {**request, "fuzzing": [{"part": "query"}]},
            "race": {**request, "race": True},
            "unsafe": {**request, "unsafe": True},
            "raw post": {"raw": ["POST /login HTTP/1.1\nHost: {{Hostname}}\n\nuser=admin"]},
            "raw body": {"raw": ["GET / HTTP/1.1\nHost: {{Hostname}}\n\nbody"]},
            "traversal": {**request, "path": ["{{BaseURL}}/../../etc/passwd"]},
            "encoded traversal": {**request, "path": ["{{BaseURL}}/%2e%2e/%2e%2e/win.ini"]},
            "script": {**request, "path": ["{{BaseURL}}/?q=<script>alert(1)</script>"]},
            "template injection": {**request, "path": ["{{BaseURL}}/${jndi:ldap://x}"]},
            "oob": {**request, "path": ["{{BaseURL}}/?u={{interactsh-url}}"]},
            "encoded payload": {**request, "path": ["{{BaseURL}}/{{base64('id')}}"]},
            "state change": {**request, "path": ["{{BaseURL}}/api/reset?user=1"]},
            "timing": {**request, "matchers": [{"type": "dsl", "dsl": ["duration>=5"]}]},
            "wordlist": {**request, "path": ["{{BaseURL}}/{{word}}"], "payloads": {"word": "helpers/wordlists/common.txt"}},
            "long payload list": {**request, "path": ["{{BaseURL}}{{p}}"], "payloads": {"p": [f"/f{index}" for index in range(61)]}},
            "payload with attack": {**request, "path": ["{{BaseURL}}{{p}}"], "payloads": {"p": ["/a", "/../b"]}},
            "attack without payloads": {**request, "attack": "clusterbomb"},
        }
        for name, item in cases.items():
            with self.subTest(case=name):
                self.assertFalse(nuclei_templates.allowed("http/exposures/sample.yaml", template(http=[item])))
        for key in ("code", "javascript", "headless", "flow", "network", "dns", "workflows"):
            with self.subTest(key=key):
                self.assertFalse(nuclei_templates.allowed("http/exposures/sample.yaml", template(**{key: [{}]})))
        self.assertFalse(nuclei_templates.allowed("http/vulnerabilities/sample.yaml", template()))  # not a detection folder
        self.assertFalse(nuclei_templates.allowed("dast/sample.yaml", template()))

    def test_a_short_list_of_fixed_paths_is_looking_but_a_cve_reads_fixed_paths_only(self):
        listed = template(http=[{"method": "GET", "path": ["{{BaseURL}}{{paths}}"], "payloads": {"paths": ["/.env", "/.env.bak", "/.env.{{DN}}"]}}])
        self.assertTrue(nuclei_templates.allowed("http/exposures/configs/env.yaml", listed))
        self.assertFalse(nuclei_templates.allowed("http/cves/2024/CVE-2024-0001.yaml", listed))
        query = template(http=[{"method": "GET", "path": ["{{BaseURL}}/status?format=json"]}])
        self.assertTrue(nuclei_templates.allowed("http/misconfiguration/status.yaml", query))
        self.assertFalse(nuclei_templates.allowed("http/cves/2024/CVE-2024-0002.yaml", query))
        self.assertTrue(nuclei_templates.allowed("http/cves/2024/CVE-2024-0003.yaml", template(http=[{"method": "GET", "path": ["{{BaseURL}}/readme.txt"]}])))

    def test_page_level_templates_read_only_the_page_they_are_given(self):
        self.assertTrue(nuclei_templates.page_level(template(http=[{"method": "GET", "path": ["{{BaseURL}}"]}])))
        self.assertFalse(nuclei_templates.page_level(template()))
        self.assertFalse(nuclei_templates.page_level({"id": "t", "info": {}, "ssl": [{}]}))

    def archive(self, files: dict[str, str]) -> bytes:
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
            for name, content in files.items():
                data = content.encode()
                info = tarfile.TarInfo(nuclei_templates.PREFIX + name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
            link = tarfile.TarInfo(nuclei_templates.PREFIX + "http/exposures/link.yaml")
            link.type, link.linkname = tarfile.SYMTYPE, "/etc/passwd"
            tar.addfile(link)
        return buffer.getvalue()

    def test_only_allowed_templates_reach_the_disk_and_a_bad_checksum_writes_nothing(self):
        data = self.archive({
            "http/exposures/configs/git.yaml": yaml.safe_dump(template()),
            "http/misconfiguration/headers.yaml": yaml.safe_dump(template(id="headers", http=[{"method": "GET", "path": ["{{BaseURL}}"]}])),
            "http/cves/2024/rce.yaml": yaml.safe_dump(template(id="rce", info={"name": "x", "severity": "critical", "tags": "cve,rce"})),
            "http/exposures/../../escape.yaml": yaml.safe_dump(template(id="escape")),
            "dast/fuzz.yaml": yaml.safe_dump(template(id="fuzz")),
            "README.md": "not a template",
        })
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(nuclei_templates.TemplatesError):
                nuclei_templates.ensure(Path(directory), fetch=lambda: data)
            self.assertEqual([path.name for path in Path(directory).iterdir()], [])
            with patch.object(nuclei_templates, "SHA256", __import__("hashlib").sha256(data).hexdigest()):
                folder, counts = nuclei_templates.ensure(Path(directory), fetch=lambda: data)
                again, _ = nuclei_templates.ensure(Path(directory), fetch=lambda: self.fail("downloaded twice"))
            written = sorted(str(path.relative_to(folder)) for path in folder.rglob("*.yaml"))
            self.assertEqual(again, folder)
            self.assertEqual(written, ["hosts/http/exposures/configs/git.yaml", "hosts/http/misconfiguration/headers.yaml",
                                       "pages/http/misconfiguration/headers.yaml"])
            self.assertEqual((counts["hosts"], counts["pages"]), (2, 1))
            self.assertFalse((Path(directory) / "escape.yaml").exists())
            for path in folder.rglob("*.yaml"):
                tags = nuclei_templates._tags(yaml.safe_load(path.read_text()))
                self.assertFalse(tags & nuclei_templates.DENY_TAGS, path)

    def test_the_release_is_pinned(self):
        self.assertRegex(nuclei_templates.SHA256, r"^[0-9a-f]{64}$")
        self.assertIn(f"/v{nuclei_templates.RELEASE}", nuclei_templates.URL)
        self.assertTrue(nuclei_templates.URL.startswith("https://codeload.github.com/projectdiscovery/nuclei-templates/"))


class ArgumentTests(unittest.TestCase):
    """What each tool is told: its scope, a dead resolver, no updates, a rate, and nothing that attacks."""

    def test_katana_crawls_the_scope_only_without_redirects_or_private_addresses(self):
        arguments = web_tools.katana_arguments([HOST, "docs.pitangus.dev"])
        scope = arguments[arguments.index("-cs") + 1]
        for url in ("https://pitangus.dev/", "https://docs.pitangus.dev/es/?q=1", "https://pitangus.dev:443/a"):
            self.assertTrue(re.match(scope, url), url)
        for url in ("http://pitangus.dev/", "https://evil.example/?u=https://pitangus.dev/", "https://pitangus.dev.evil.example/",
                    "https://api.pitangus.dev/", "https://pitangus.dev@evil.example/", "https://169.254.169.254/", "https://pitangus.dev:8443/"):
            self.assertFalse(re.match(scope, url), url)
        for flag in ("-dr", "-duc", "-iqp", "-silent"):
            self.assertIn(flag, arguments)
        self.assertEqual(arguments[arguments.index("-e") + 1], "private-ips")
        self.assertEqual(arguments[arguments.index("-r") + 1], f"{web_tools.WORK}/{web_tools.RESOLVERS}")
        self.assertLessEqual(int(arguments[arguments.index("-rl") + 1]), 10)
        self.assertNotIn("-aff", arguments)  # never fills forms
        self.assertIn("--proxy-bypass-list=pitangus.dev;docs.pitangus.dev", arguments)
        self.assertIn("--proxy-server=http://127.0.0.1:9", arguments)
        self.assertNotIn("-hh", web_tools.katana_arguments([HOST], headless=False))

    def test_nuclei_runs_only_mounted_templates_and_never_calls_out(self):
        arguments = web_tools.nuclei_arguments("hosts", 10)
        self.assertEqual(arguments[arguments.index("-t") + 1], "/templates/hosts")
        for flag in ("-duc", "-ni", "-dr", "-lna", "-no-stdin", "-or"):
            self.assertIn(flag, arguments)
        for flag in ("-ut", "-update-templates", "-up", "-dast", "-fuzz", "-headless", "-code", "-esc", "-lfa", "-iserver", "-fr", "-cloud-upload",
                     "-dashboard", "-as", "-tlsi"):
            self.assertNotIn(flag, arguments)
        excluded = set(arguments[arguments.index("-etags") + 1].split(","))
        self.assertEqual(excluded, set(nuclei_templates.DENY_TAGS))
        self.assertEqual(set(arguments[arguments.index("-ept") + 1].split(",")),
                         {"headless", "code", "javascript", "file", "dns", "tcp", "websocket", "whois", "workflow"})
        self.assertLessEqual(int(arguments[arguments.index("-rl") + 1]), 10)
        self.assertEqual(arguments[arguments.index("-mt") + 1], "10m")

    def test_testssl_connects_to_the_pinned_address_without_dns_calls_out_or_vulnerability_checks(self):
        arguments = web_tools.testssl_arguments(HOST, "172.67.153.40", "testssl-0.json")
        self.assertEqual(arguments[arguments.index("--ip") + 1], "172.67.153.40")
        self.assertEqual(arguments[arguments.index("--nodns") + 1], "none")
        self.assertEqual(arguments[-1], f"https://{HOST}/")
        for flag in ("--phone-out", "-U", "--vulnerable", "-H", "--heartbleed", "-R", "--robot", "-e", "--each-cipher", "--ssl-native"):
            self.assertNotIn(flag, arguments)

    def test_httpx_reaches_only_the_pinned_addresses(self):
        arguments = web_tools.httpx_arguments(["172.67.153.40", "104.21.32.173", "172.67.153.40"])
        self.assertEqual(arguments[arguments.index("-allow") + 1], "104.21.32.173,172.67.153.40")
        for flag in ("-duc", "-nfs", "-no-stdin", "-ob"):
            self.assertIn(flag, arguments)
        for flag in ("-fr", "-ss", "-screenshot", "-x", "-pa", "-tls-probe", "-csp-probe", "-vhost"):
            self.assertNotIn(flag, arguments)


def fake_tools(outputs: dict, *, calls: list | None = None, returncodes: dict | None = None, raising: dict | None = None,
               errors: dict | None = None):
    """`docker run` of the web tools: answers each image with its fixture (stdout, or testssl.sh's JSON report written
    into its work folder; `errors`: its stderr), and ZAP with a real SARIF."""
    images = {meta["image"]: key for key, meta in engines.IMAGES.items()}

    def run(command, **kwargs):
        key = next((images[part] for part in command if part in images), None)
        if key is None:  # `docker rm --force` after a timeout
            return subprocess.CompletedProcess(command, 0, "", "")
        if calls is not None:
            calls.append((key, command, kwargs.get("input")))
        if raising and key in raising:
            raise raising[key]
        mounts = [command[index + 1] for index, part in enumerate(command) if part == "-v"]
        if key == "zap":
            work = Path(mounts[0].rsplit(":", 2)[0])
            (work / web.REPORT).write_text(fixture("zap-2.17.sarif"))
        if key == "testssl":
            work = Path(mounts[0].rsplit(":", 2)[0])
            report = command[command.index("--jsonfile") + 1].rsplit("/", 1)[-1]
            (work / report).write_text(outputs.get("testssl", "[]"))
            return subprocess.CompletedProcess(command, (returncodes or {}).get(key, 0), "", "")
        return subprocess.CompletedProcess(command, (returncodes or {}).get(key, 0), outputs.get(key, ""), (errors or {}).get(key, ""))
    return patch("pitangus.modules.scanning.engines.subprocess.run", side_effect=run)


class ContainerTests(unittest.TestCase):
    def setUp(self):
        testenv.docker_runner(self)
        which = patch.object(engines.shutil, "which", return_value="/usr/bin/docker")
        which.start()
        self.addCleanup(which.stop)
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.work = Path(self.directory.name)

    def options(self, command: list) -> list:
        image = next(index for index, part in enumerate(command) if "@sha256:" in part)
        return command[:image]

    def assert_hardened(self, key: str, command: list, *, pins=PINS):
        options = self.options(command)

        def values(flag):
            return [options[index + 1] for index, item in enumerate(options) if item == flag]
        self.assertEqual(values("--cap-drop"), ["ALL"])
        self.assertEqual(values("--security-opt"), ["no-new-privileges"])
        self.assertIn("--read-only", options)
        self.assertEqual(values("--memory"), ["3g"])
        self.assertEqual(values("--cpus"), ["2"])
        self.assertEqual(values("--pids-limit"), ["512"])
        self.assertEqual(values("--network"), ["bridge"])
        self.assertEqual(values("--dns"), ["127.0.0.1"])
        self.assertEqual(sorted(values("--add-host")), sorted(f"{host}:{address}" for host, address in pins.items()))
        self.assertEqual(len(values("--user")), 1)  # our uid, never the image's root
        self.assertTrue(all(not part.endswith(":/src:ro") for part in options))
        self.assertIn(engines.IMAGES[key]["image"], command)
        self.assertRegex(engines.IMAGES[key]["image"], r"@sha256:[0-9a-f]{64}$")
        (tmpfs,) = values("--tmpfs")
        self.assertIn("exec" if key == "katana" else "noexec", tmpfs.split(","))
        for mount in values("-v"):
            self.assertTrue(mount.endswith(":ro") or (key == "testssl" and mount.endswith(":rw")), mount)

    def test_each_tool_runs_hardened_and_reaches_only_the_pinned_hosts(self):
        calls = []
        outputs = {"katana": fixture("katana-1.7.jsonl"), "nuclei": fixture("nuclei-3.11.jsonl"), "httpx": fixture("httpx-1.12.jsonl"),
                   "testssl": fixture("testssl-3.2.json")}
        cache = self.work / "templates"
        (cache / f"v{nuclei_templates.RELEASE}" / "hosts").mkdir(parents=True)
        (cache / f"v{nuclei_templates.RELEASE}" / nuclei_templates.COMPLETE).write_text(json.dumps({"hosts": 1, "pages": 0}))
        with fake_tools(outputs, calls=calls):
            web_tools.run_katana([f"https://{HOST}/"], [HOST], PINS, self.work)
            web_tools.run_nuclei([f"https://{HOST}/"], [f"https://{HOST}/es/"], [HOST], PINS, self.work, cache)
            web_tools.run_testssl([HOST], PINS, self.work)
            web_tools.run_httpx([HOST], PINS, self.work)
        self.assertEqual([key for key, _, _ in calls], ["katana", "nuclei", "nuclei", "testssl", "httpx"])
        for key, command, _ in calls:
            with self.subTest(tool=key):
                self.assert_hardened(key, command)
        nuclei = calls[1][1]
        self.assertTrue(any(part.endswith(":/templates:ro") for part in nuclei))

    def test_saved_headers_reach_katana_and_nuclei_on_standard_input_only(self):
        secret = "Bearer eyJhbGciOiJIUzI1NiJ9.c2VjcmV0LXRva2Vu"
        calls = []
        cache = self.work / "templates"
        (cache / f"v{nuclei_templates.RELEASE}" / "hosts").mkdir(parents=True)
        (cache / f"v{nuclei_templates.RELEASE}" / nuclei_templates.COMPLETE).write_text("{}")
        echoed = json.dumps({"template-id": "t", "info": {"name": "t", "severity": "low"}, "matched-at": f"https://{HOST}/",
                             "curl-command": f"curl -H 'Authorization: {secret}' https://{HOST}/"})
        with fake_tools({"katana": "", "nuclei": echoed}, calls=calls):
            web_tools.run_katana([f"https://{HOST}/"], [HOST], PINS, self.work, headers=[("Authorization", secret)])
            run, _ = web_tools.run_nuclei([f"https://{HOST}/"], [], [HOST], PINS, self.work, cache, headers=[("Authorization", secret)],
                                          scrub=lambda value: value.replace(secret, "[redacted]"))
        for key, command, given in calls[:2]:
            with self.subTest(tool=key):
                self.assertNotIn(secret, json.dumps(command))
                self.assertEqual(given, f"Authorization: {secret}\n")
                self.assertEqual(command[command.index("--entrypoint") + 1], "sh")
                self.assertIn(f"-H {web_tools.HEADERS_FILE}", command[command.index("-c") + 1])
                self.assertTrue(web_tools.HEADERS_FILE.startswith("/tmp/"))  # the memory-only tmpfs, never a mounted folder
        self.assertNotIn(secret, json.dumps(run.findings))
        with self.assertRaises(ValueError):
            web_tools._wrap("katana", [], [("X-Evil", "a\nb")])

    def test_a_tool_never_runs_against_an_unpinned_host(self):
        with fake_tools({}, calls=[]), self.assertRaises(ValueError):
            web_tools.run_katana([f"https://{HOST}/"], [HOST, "docs.pitangus.dev"], PINS, self.work)
        with fake_tools({}), self.assertRaises(ValueError):
            web_tools.run_httpx(["docs.pitangus.dev"], PINS, self.work)

    def test_the_images_are_listed_and_pulled_only_with_web_scans_on(self):
        for key in web_tools.TOOLS:
            self.assertIn(key, engines.WEB_ENGINES)
            self.assertNotIn(key, engines.BINARIES)
        with patch.dict("os.environ", {"PITANGUS_ENGINE_RUNNER": "local"}):
            self.assertTrue(all(reason is not None for reason in web_tools.readiness().values()))


class ScopeTests(unittest.TestCase):
    def test_only_https_urls_on_the_pinned_hosts_count_without_their_query(self):
        hosts = [HOST]
        self.assertEqual(web_tools.in_scope_url("https://pitangus.dev/es/?token=abc#x", hosts), "https://pitangus.dev/es/")
        self.assertEqual(web_tools.in_scope_url("https://PITANGUS.dev", hosts), "https://pitangus.dev/")
        for url in ("http://pitangus.dev/", "https://pitangus.dev:8443/", "https://user:pass@pitangus.dev/", "https://172.67.153.40/",
                    "https://docs.pitangus.dev/", "https://pitangus.dev.evil.example/", "https://pitangus.dev/${PITANGUS_LOGIN_1_PASSWORD}",
                    "javascript:alert(1)", None, "https://" + "a" * 3000):
            self.assertIsNone(web_tools.in_scope_url(url, hosts), url)


class ParserTests(unittest.TestCase):
    """Real outputs (see the module's docstring)."""

    def test_katana_keeps_in_scope_urls_and_drops_the_rest(self):
        urls = web_tools.parse_katana(fixture("katana-1.7.jsonl"), [HOST])
        self.assertIn(f"https://{HOST}/", urls)
        self.assertTrue(urls)
        self.assertTrue(all(url.startswith(f"https://{HOST}/") and "?" not in url for url in urls))
        edge = web_tools.parse_katana(fixture("katana-1.7-edge.jsonl"), [EDGE])
        self.assertEqual(edge, [f"https://{EDGE}/", f"https://{EDGE}/about.html", f"https://{EDGE}/old"])
        self.assertNotIn("169.254.169.254", json.dumps(edge))
        self.assertEqual(web_tools.parse_katana('{"request": {"method": "POST", "endpoint": "https://pitangus.dev/x"}}\nnot json\n', [HOST]), [])

    def test_nuclei_results_become_findings_with_the_templates_own_text(self):
        findings, technologies = web_tools.parse_nuclei(fixture("nuclei-3.11-edge.jsonl"), [EDGE])
        by_rule = {item["rule_id"]: item for item in findings}
        git = by_rule["git-config"]
        self.assertEqual((git["scanner"], git["tool"], git["severity"], git["path"], git["cwe"]),
                         ("dast", "nuclei", "medium", f"https://{EDGE}/.git/config", [200]))
        self.assertIn("Git configuration was detected", git["web"]["description"])
        self.assertEqual(text(git["remediation"], "en"), text(web.msg("scanning.web.remediation", tool="nuclei"), "en"))  # it gives none
        headers = by_rule["http-missing-security-headers:strict-transport-security"]
        self.assertEqual((headers["web"]["parameter"], headers["severity"]), ("strict-transport-security", "info"))
        self.assertIn("self-signed-ssl", by_rule)
        self.assertEqual(by_rule["self-signed-ssl"]["path"], f"https://{EDGE}/")
        self.assertIn("Nginx", {item["name"] for item in technologies})
        self.assertIn("1.27.5", {item["version"] for item in technologies})
        stored = json.dumps(findings)
        for leaked in ("curl-command", "extracted-results", "repositoryformatversion", "abc123"):
            self.assertNotIn(leaked, stored)
        real, _ = web_tools.parse_nuclei(fixture("nuclei-3.11.jsonl"), [HOST])
        self.assertTrue(all(item["path"].startswith(f"https://{HOST}/") for item in real))
        self.assertFalse({"ssl-dns-names", "wildcard-tls", "tls-version", "ssl-issuer"} & {item["rule_id"] for item in real})
        # A result about a host outside the scope is never a finding.
        self.assertEqual(web_tools.parse_nuclei(fixture("nuclei-3.11-edge.jsonl"), [HOST]), ([], []))

    def test_nuclei_remediation_is_shown_verbatim_when_the_template_has_one(self):
        line = json.dumps({"template-id": "t", "matched-at": f"https://{HOST}/x", "info": {
            "name": "Thing", "severity": "high", "remediation": "Remove the file.", "reference": ["https://example.org/a", "ftp://x"],
            "classification": {"cwe-id": ["CWE-200"], "cve-id": ["CVE-2024-12345", "nope"]}}})
        (finding,), _ = web_tools.parse_nuclei(line, [HOST])
        self.assertIn("Remove the file.", text(finding["remediation"], "en"))
        self.assertEqual((finding["cve"], finding["cwe"], finding["web"]["references"]), (["CVE-2024-12345"], [200], ["https://example.org/a"]))
        self.assertEqual(finding["priority"]["action"], "attend")

    def test_testssl_keeps_what_it_rates_low_or_worse_and_folds_cipher_lines(self):
        findings = web_tools.parse_testssl(json.loads(fixture("testssl-3.2.json")), HOST)
        self.assertEqual([(item["rule_id"], item["severity"]) for item in findings], [("cipherlist_OBSOLETED", "low")])
        self.assertIn("ECDHE-ECDSA-AES128-SHA", findings[0]["web"]["evidence"])
        self.assertEqual((findings[0]["tool"], findings[0]["path"], findings[0]["cwe"]), ("testssl", f"https://{HOST}/", [310]))
        edge = {item["rule_id"]: item for item in web_tools.parse_testssl(json.loads(fixture("testssl-3.2-edge.json")), EDGE)}
        self.assertEqual(edge["cert_chain_of_trust"]["severity"], "critical")
        self.assertEqual(edge["HSTS"]["severity"], "low")
        self.assertFalse({"engine_problem", "scanTime", "service"} & set(edge))
        self.assertFalse(any(rule.startswith("cipher-") for rule in edge))
        self.assertEqual(web_tools.parse_testssl({"not": "a list"}, HOST), [])

    def test_httpx_names_technologies_with_their_versions(self):
        detected = web_tools.parse_httpx(fixture("httpx-1.12.jsonl"), [HOST, EDGE])
        rows = web_tools.technologies_of(detected, [{"name": "cloudflare", "host": HOST}, {"name": "nginx", "version": None, "host": EDGE}])
        names = {(row["name"], row.get("version")) for row in rows}
        self.assertIn(("Cloudflare", None), names)
        self.assertIn(("Nginx", "1.27.5"), names)
        self.assertNotIn(("nginx", None), names)  # the version-less, lower-case twin adds nothing
        self.assertNotIn(("cloudflare", None), names)
        self.assertEqual(web_tools.parse_httpx('{"host": "evil.example", "tech": ["X:1"]}', [HOST]), [])


class SilentFailureTests(unittest.TestCase):
    """A tool that exits 0 without reaching a host: the samples are real (nuclei 3.11, katana 1.7 and testssl.sh 3.2
    with pitangus.dev pinned to 203.0.113.7, a documentation address nothing answers on, which nuclei's `-lna` also
    refuses; edge.pitangus.test pinned to the container's loopback). Each exited 0 (testssl.sh 246) and printed no
    finding."""

    def setUp(self):
        testenv.docker_runner(self)
        which = patch.object(engines.shutil, "which", return_value="/usr/bin/docker")
        which.start()
        self.addCleanup(which.stop)
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.work = Path(self.directory.name)
        self.cache = self.work / "templates"
        (self.cache / f"v{nuclei_templates.RELEASE}" / "hosts").mkdir(parents=True)
        (self.cache / f"v{nuclei_templates.RELEASE}" / "pages").mkdir(parents=True)
        (self.cache / f"v{nuclei_templates.RELEASE}" / nuclei_templates.COMPLETE).write_text(json.dumps({"hosts": 1, "pages": 1}))

    def test_nuclei_log_names_the_hosts_it_skipped_and_reads_its_last_statistics(self):
        self.assertEqual(web_tools.nuclei_log(fixture("nuclei-3.11-skipped.log"), [HOST]), ({HOST}, True))
        self.assertEqual(web_tools.nuclei_log(fixture("nuclei-3.11-denied.log"), [EDGE]), ({EDGE}, True))
        self.assertEqual(web_tools.nuclei_log(fixture("nuclei-3.11-stats.log"), [HOST]), (set(), False))
        # As nuclei 3 logs a template that couldn't run (pkg/tmplexec): the pass is incomplete, the host named.
        unexecuted = f"[WRN] [tech-detect] Could not execute request for https://{HOST}/: context deadline exceeded\n"
        self.assertEqual(web_tools.nuclei_log(unexecuted, [HOST]), ({HOST}, True))
        self.assertEqual(web_tools.nuclei_log('{"percent":"74","errors":"3"}\n', [HOST]), (set(), True))
        # A host outside the scope still leaves the pass incomplete, without being named.
        self.assertEqual(web_tools.nuclei_log("[INF] Skipped evil.example:443 from target list as found unresponsive permanently\n", [HOST]),
                         (set(), True))

    def test_nuclei_that_skipped_a_host_is_partial_and_names_it(self):
        with fake_tools({"nuclei": ""}, errors={"nuclei": fixture("nuclei-3.11-skipped.log")}):
            run, _ = web_tools.run_nuclei([f"https://{HOST}/"], [f"https://{HOST}/es/"], [HOST], PINS, self.work, self.cache)
        self.assertEqual((run.status, run.unreached), ("partial", [HOST]))
        self.assertIn(f"couldn't check {HOST}", text(run.detail, "en"))
        with fake_tools({"nuclei": ""}, errors={"nuclei": fixture("nuclei-3.11-stats.log")}):
            clean, _ = web_tools.run_nuclei([f"https://{HOST}/"], [], [HOST], PINS, self.work, self.cache)
        self.assertEqual((clean.status, clean.unreached), ("completed", []))

    def test_nuclei_reports_progress_on_stderr_instead_of_staying_silent(self):
        arguments = web_tools.nuclei_arguments("hosts", 10)
        self.assertNotIn("-silent", arguments)
        for flag in ("-stats", "-sj", "-nc", "-jsonl"):
            self.assertIn(flag, arguments)

    def test_katana_that_reached_nothing_is_partial(self):
        output = fixture("katana-1.7-unreachable.jsonl")
        self.assertEqual(web_tools.parse_katana(output, [HOST]), [])  # the errored seed isn't a URL found
        self.assertEqual(web_tools.katana_reached(output, [HOST]), set())
        self.assertEqual(web_tools.katana_reached(fixture("katana-1.7.jsonl"), [HOST]), {HOST})
        with fake_tools({"katana": output}):
            run, urls = web_tools.run_katana([f"https://{HOST}/"], [HOST], PINS, self.work, headless=False)
        self.assertEqual((run.status, run.unreached, urls), ("partial", [HOST], []))

    def test_testssl_that_couldnt_connect_is_partial(self):
        document = json.loads(fixture("testssl-3.2-unreachable.json"))
        self.assertFalse(web_tools.testssl_finished(document))
        self.assertTrue(web_tools.testssl_finished(json.loads(fixture("testssl-3.2.json"))))
        self.assertFalse(web_tools.testssl_finished([{"id": "scanTime", "finding": "Scan interrupted"}]))
        with fake_tools({"testssl": fixture("testssl-3.2-unreachable.json")}, returncodes={"testssl": 246}):
            run = web_tools.run_testssl([HOST], PINS, self.work)
        self.assertEqual((run.status, run.unreached, run.findings), ("partial", [HOST], []))

    def test_httpx_without_an_answer_is_partial(self):
        self.assertEqual(web_tools.httpx_answered(fixture("httpx-1.12.jsonl"), [HOST]), {HOST})
        with fake_tools({"httpx": ""}):
            run, detected = web_tools.run_httpx([HOST], PINS, self.work)
        self.assertEqual((run.status, run.unreached, detected), ("partial", [HOST], []))


def finding(tool: str, rule: str, path: str, severity: str = "low", **extra) -> dict:
    return {"finding_id": rule[:16], "fingerprint": f"{tool}:{rule}:{path}", "scanner": "dast", "tool": tool, "rule_id": rule, "title": rule,
            "path": path, "line": 1, "severity": severity, "confidence": 6, "priority": {"action": "track", "factors": []}, **extra}


class MergeTests(unittest.TestCase):
    def test_the_same_problem_at_the_same_url_is_one_finding_listing_every_tool(self):
        zap = finding("ZAP", "10035", f"https://{HOST}/", "low", web={"evidence": "no header"})
        nuclei = finding("nuclei", "http-missing-security-headers:strict-transport-security", f"https://{HOST}/", "info")
        testssl = finding("testssl", "HSTS", f"https://{HOST}", "medium", web={"evidence": "not offered"})
        merged, folded = web_merge.merge([testssl, nuclei, zap])
        self.assertEqual((len(merged), folded), (1, 2))
        (only,) = merged
        self.assertEqual(only["fingerprint"], zap["fingerprint"])  # ZAP keeps it: its fingerprints predate the others
        self.assertEqual(only["also_detected_by"], ["nuclei", "testssl"])
        self.assertEqual(only["related_rules"], ["http-missing-security-headers:strict-transport-security", "HSTS"])
        self.assertEqual(only["severity"], "medium")
        self.assertEqual(only["confidence"], 8)
        self.assertEqual([item["tool"] for item in only["web"]["also"]], ["nuclei", "testssl"])
        self.assertEqual(only["web"]["also"][1]["evidence"], "not offered")
        self.assertEqual(only["web"]["evidence"], "no header")

    def test_different_urls_problems_or_the_same_tool_twice_stay_apart(self):
        cases = [
            [finding("ZAP", "10035", f"https://{HOST}/"), finding("nuclei", "http-missing-security-headers:strict-transport-security", f"https://{HOST}/es/")],
            [finding("ZAP", "10035", f"https://{HOST}/"), finding("nuclei", "http-missing-security-headers:content-security-policy", f"https://{HOST}/")],
            [finding("ZAP", "10038", f"https://{HOST}/"), finding("ZAP", "10038", f"https://{HOST}/")],
            [finding("ZAP", "10055", f"https://{HOST}/"), finding("nuclei", "csp-script-src-wildcard", f"https://{HOST}/")],  # no mapping
            [finding("ZAP", "10010", f"https://{HOST}/", cwe=[1004]), finding("nuclei", "other", f"https://{HOST}/", cwe=[1004])],  # CWE alone
        ]
        for items in cases:
            with self.subTest(rules=[item["rule_id"] for item in items]):
                merged, folded = web_merge.merge(items)
                self.assertEqual((len(merged), folded), (2, 0))
                self.assertFalse(any(item.get("also_detected_by") for item in merged))

    def test_the_mapping_names_rules_each_tool_really_reports(self):
        self.assertEqual(web_merge.family_of(finding("ZAP", "10035-1", f"https://{HOST}/")), "hsts-missing")
        self.assertEqual(web_merge.family_of(finding("testssl", "cert_chain_of_trust", f"https://{HOST}/")),
                         web_merge.family_of(finding("nuclei", "self-signed-ssl", f"https://{HOST}/")))
        self.assertIsNone(web_merge.family_of(finding("nuclei", "HSTS", f"https://{HOST}/")))  # a rule counts for its own tool only
        for family, tools in web_merge.EQUIVALENT.items():
            with self.subTest(family=family):
                self.assertGreaterEqual(len(tools), 2)
                self.assertTrue(set(tools) <= set(web_merge.ORDER))


class PipelineTests(unittest.TestCase):
    """katana → ZAP (with katana's URLs) → nuclei → testssl.sh → httpx, in one scan."""

    def setUp(self):
        testenv.docker_runner(self)
        which = patch.object(engines.shutil, "which", return_value="/usr/bin/docker")
        which.start()
        self.addCleanup(which.stop)
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.data_dir = Path(self.directory.name)
        cache = self.data_dir / "nuclei-templates" / f"v{nuclei_templates.RELEASE}"
        (cache / "hosts").mkdir(parents=True)
        (cache / nuclei_templates.COMPLETE).write_text(json.dumps({"hosts": 2392, "pages": 833}))
        self.record = {"id": "a" * 24, "host": HOST, "url": f"https://{HOST}/", "kind": "web", "key": f"domain:{HOST}"}
        self.outputs = {"katana": fixture("katana-1.7.jsonl"), "nuclei": fixture("nuclei-3.11.jsonl"), "httpx": fixture("httpx-1.12.jsonl"),
                        "testssl": fixture("testssl-3.2.json")}

    def scan(self, *, ready=None, **options):
        calls, inputs = [], []
        with fake_tools(self.outputs, calls=calls, **options):
            result = web.scan_domain(self.record, PINS["pitangus.dev"], data_dir=self.data_dir, tools=ready or dict.fromkeys(web_tools.TOOLS),
                                     progress=lambda level, message: inputs.append((level, text(message, "en"))))
        return result, calls, inputs

    def test_every_tool_runs_in_order_and_reports_its_step(self):
        result, calls, progress = self.scan()
        # pitangus.dev's crawl found scripts only: no page for nuclei's page-level pass (ContainerTests runs it).
        self.assertEqual([key for key, _, _ in calls], ["katana", "zap", "nuclei", "testssl", "httpx"])
        steps = [(step["id"], step["status"]) for step in result["steps"]]
        self.assertEqual(steps, [("dast-katana", "completed"), ("dast", "completed"), ("dast-nuclei", "completed"), ("dast-testssl", "completed"),
                                 ("dast-httpx", "completed"), ("dast-versions", "completed"), ("dast-merge", "completed"), ("active", "not_tested"),
                                 ("review", "pending")])
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["web_inventory"]["tool"], "katana")
        self.assertIn(f"https://{HOST}/", result["web_inventory"]["urls"])
        self.assertTrue({"ZAP", "nuclei", "testssl"} <= {item["tool"] for item in result["findings"]})
        self.assertTrue(all(item["web"]["coverage"] == "baseline" for item in result["findings"]))
        self.assertIn("Cloudflare", {row["name"] for row in result["summary"]["technologies"]})
        self.assertEqual({tool["name"]: tool["status"] for tool in result["summary"]["tools"]},
                         {"ZAP": "completed", "katana": "completed", "nuclei": "completed", "testssl": "completed", "httpx": "completed",
                          "httpx + OSV": "completed"})
        # ZAP got katana's URLs to request before its spider (other than where the spider starts).
        plan = json.loads(calls[1][2])
        self.assertEqual(plan["jobs"][1], {"type": "import", "parameters": {"type": "url", "fileName": f"{web.WORK}/{web.SEEDS}"}})
        self.assertTrue(any("katana" in line for _, line in progress))

    def test_a_failing_tool_leaves_its_step_partial_and_the_scan_goes_on(self):
        result, calls, _ = self.scan(returncodes={"httpx": 1}, raising={"nuclei": subprocess.TimeoutExpired(["docker"], 60), "katana": OSError("boom")})
        statuses = {step["id"]: step["status"] for step in result["steps"]}
        self.assertEqual((statuses["dast-katana"], statuses["dast-nuclei"], statuses["dast-httpx"], statuses["dast"]),
                         ("partial", "partial", "partial", "completed"))
        self.assertEqual(result["status"], "completed")  # ZAP finished: the partial tools are in the steps and the limitations
        self.assertEqual({tool["name"]: tool["status"] for tool in result["summary"]["tools"]}["nuclei"], "inconclusive")
        limitations = " ".join(text(item, "en") for item in result["limitations"])
        self.assertIn("nuclei didn't finish", limitations)
        self.assertNotIn("import", [job["type"] for job in json.loads(next(given for key, _, given in calls if key == "zap"))["jobs"]])

    def test_nuclei_exiting_0_without_reaching_the_host_is_not_a_clean_result(self):
        self.outputs["nuclei"] = ""
        result, _, _ = self.scan(errors={"nuclei": fixture("nuclei-3.11-skipped.log")})
        step = next(step for step in result["steps"] if step["id"] == "dast-nuclei")
        self.assertEqual(step["status"], "partial")
        self.assertEqual({tool["name"]: tool["status"] for tool in result["summary"]["tools"]}["nuclei"], "inconclusive")
        limitations = " ".join(text(item, "en") for item in result["limitations"])
        self.assertIn(f"nuclei couldn't check {HOST}", limitations)
        self.assertNotIn("nuclei didn't finish", limitations)

    def test_a_tool_without_its_image_is_skipped_with_the_reason(self):
        ready = {**dict.fromkeys(web_tools.TOOLS), "testssl": web.msg("scanning.web.tools.image_missing", tool="testssl.sh")}
        result, calls, _ = self.scan(ready=ready)
        self.assertNotIn("testssl", [key for key, _, _ in calls])
        step = next(step for step in result["steps"] if step["id"] == "dast-testssl")
        self.assertEqual(step["status"], "skipped")
        self.assertIn("make engines", text(step["detail"], "en"))

    def test_without_the_tools_the_scan_is_zap_alone(self):
        calls = []
        with fake_tools(self.outputs, calls=calls):
            result = web.scan_domain(self.record, PINS["pitangus.dev"], data_dir=self.data_dir)
        self.assertEqual([key for key, _, _ in calls], ["zap"])
        self.assertNotIn("web_inventory", result)
        self.assertEqual([step["id"] for step in result["steps"]], ["dast", "active", "review"])


if __name__ == "__main__":
    unittest.main()
