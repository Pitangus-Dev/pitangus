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

    def test_the_status_pass_asks_each_url_over_its_scheme_reads_a_bounded_body_and_follows_nothing(self):
        arguments = web_tools.httpx_status_arguments(["172.67.153.40"])
        self.assertEqual(arguments[arguments.index("-allow") + 1], "172.67.153.40")
        for flag in ("-nfs", "-irr", "-duc", "-no-stdin"):
            self.assertIn(flag, arguments)
        self.assertEqual(int(arguments[arguments.index("-rstr") + 1]), web_tools.BODY_READ)
        for flag in ("-fr", "-fhr", "-ob", "-sr", "-store-response", "-x"):
            self.assertNotIn(flag, arguments)


def fake_tools(outputs: dict, *, calls: list | None = None, returncodes: dict | None = None, raising: dict | None = None,
               errors: dict | None = None):
    """`docker run` of the web tools: answers each image with its fixture (stdout, or testssl.sh's JSON report written
    into its work folder; `errors`: its stderr), and ZAP with a real SARIF. nuclei prints its final statistics on
    stderr, as it does on every run that read its targets, unless `errors` says otherwise."""
    images = {meta["image"]: key for key, meta in engines.IMAGES.items()}
    errors = {"nuclei": fixture("nuclei-3.11-stats.log"), **(errors or {})}

    def run(command, **kwargs):
        key = next((images[part] for part in command if part in images), None)
        if key is None:  # `docker rm --force` after a timeout
            return subprocess.CompletedProcess(command, 0, "", "")
        if calls is not None:
            calls.append((key, command, kwargs.get("input")))
        if raising and key in raising:
            raise raising[key]
        mounts = [command[index + 1] for index, part in enumerate(command) if part == "-v"]
        statuses = outputs.get("statuses", {})
        if key == "zap":
            work = Path(mounts[0].rsplit(":", 2)[0])
            (work / web.REPORT).write_text(fixture("zap-2.17.sarif"))
            if "zap_urls" in outputs:
                (work / web.EXPORT).write_text(outputs["zap_urls"])
                # Its sites tree: each URL it requested with the status it got (200 unless set), as ZAP 2.17 exports it.
                urls = [line.strip() for line in outputs["zap_urls"].splitlines() if line.strip().startswith("http")]
                (work / web.TREE).write_text(yaml.safe_dump([{"node": "Sites", "children": [
                    {"node": f"GET:{url}", "url": url, "method": "GET", "statusCode": outputs.get("zap_statuses", statuses).get(url, 200)}
                    for url in urls]}]))
        if key == "nuclei":  # each response it got, as its stored responses give them (web_tools.NUCLEI_STATUS_AWK)
            work = Path(mounts[0].rsplit(":", 2)[0])
            targets = (work / "targets.txt").read_text().split()
            pages = "/templates/pages" in command
            asked = [url for target in targets for url in ([target] if pages else
                                                            [target, *(target.rstrip("/") + path for path in web.known_paths())])]
            (work / web_tools.NUCLEI_STATUSES).write_text("".join(f"{url} {statuses.get(url, 200)}\n" for url in asked))
        if key == "testssl":
            work = Path(mounts[0].rsplit(":", 2)[0])
            report = command[command.index("--jsonfile") + 1].rsplit("/", 1)[-1]
            (work / report).write_text(outputs.get("testssl", "[]"))
            return subprocess.CompletedProcess(command, (returncodes or {}).get(key, 0), "", "")
        if key == "httpx" and f"{web_tools.WORK}/pages.txt" in command:  # the status pass: each page its status (200 unless set)
            work = Path(mounts[0].rsplit(":", 2)[0])
            pages = (work / "pages.txt").read_text().split()
            outputs["checked"] = pages
            lines = "".join(json.dumps({"input": url, "url": url, "status_code": statuses.get(url, 200)}) + "\n" for url in pages)
            return subprocess.CompletedProcess(command, 0, lines, "")
        return subprocess.CompletedProcess(command, (returncodes or {}).get(key, 0), outputs.get(key, ""), errors.get(key, ""))
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
            # testssl.sh writes its report, nuclei its trace log (the requests it sent), each in its own private folder.
            writable = key in ("testssl", "nuclei") and mount.endswith(f":{web_tools.WORK}:rw")
            self.assertTrue(mount.endswith(":ro") or writable, mount)

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
        # /old answered 301: the page is where it points, and checking the redirect's headers again only repeats them.
        self.assertEqual(edge, [f"https://{EDGE}/", f"https://{EDGE}/about.html"])
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

    def test_a_tech_tagged_template_of_higher_severity_is_a_finding(self):
        """Only the technologies folder, or a `tech` template that informs, names a technology."""
        line = json.dumps({"template-id": "unauth-etcd-server", "template-path": "/templates/hosts/http/misconfiguration/etcd.yaml",
                           "info": {"name": "etcd unauthenticated", "severity": "high", "tags": ["tech", "etcd", "unauth"]},
                           "matched-at": f"https://{EDGE}/v2/keys", "host": EDGE, "type": "http"})
        findings, technologies = web_tools.parse_nuclei(line + "\n", [EDGE])
        self.assertEqual([(item["rule_id"], item["severity"]) for item in findings], [("unauth-etcd-server", "high")])
        self.assertEqual(technologies, [])

    def test_what_nuclei_printed_before_running_out_of_time_opens_nothing(self):
        """A pass that didn't finish neither opens nor closes: half a run's matches may be all it would have said."""
        import subprocess
        partial = fixture("nuclei-3.11-edge.jsonl").encode()
        with patch.object(web_tools, "_run", side_effect=subprocess.TimeoutExpired(["nuclei"], 60, output=partial, stderr=b"")), \
                patch.object(web_tools.nuclei_templates, "ensure", return_value=(Path("/tmp"), {"hosts": 1})), \
                patch.object(web_tools.nuclei_templates, "ensure_own", return_value=(None, {})), \
                patch.object(web_tools, "_pins_ok"):
            run, _ = web_tools.run_nuclei([f"https://{EDGE}/"], [], [EDGE], {EDGE: "203.0.113.7"}, Path("/tmp"), Path("/tmp"))
        self.assertEqual((run.status, run.findings, run.coverage()["examined"]), ("partial", [], []))

    def test_nucleis_stored_responses_give_its_own_status_for_each_page(self):
        """nuclei 3.11's stored responses (-sresp, a throwaway local site), read by the line the container runs after
        it: each response's URL and status, never a header or a body."""
        lines = subprocess.run(["awk", web_tools.NUCLEI_STATUS_AWK, str(OUTPUTS / "nuclei-3.11-responses.txt")], capture_output=True, text=True,
                               check=True).stdout
        self.assertEqual(lines.split("\n")[:3], [f"http://{EDGE}/.env 429", f"http://{EDGE}/forbidden 403", f"http://{EDGE}/missing 404"])
        self.assertEqual(web_tools.nuclei_statuses(lines, [EDGE]), [])  # plain HTTP counts only where the scan asked for it
        answers = web_tools.nuclei_statuses(lines + f"https://{EDGE}//a/b 200\nhttps://evil.example/ 200\nnot a line\n", [EDGE], http=True)
        self.assertEqual(answers, [(f"http://{EDGE}/.env", 429), (f"http://{EDGE}/forbidden", 403), (f"http://{EDGE}/missing", 404),
                                   (f"https://{EDGE}/a/b", 200)])
        arguments = web_tools.nuclei_arguments("hosts", 10)
        self.assertEqual(arguments[arguments.index("-srd") + 1], web_tools.NUCLEI_STORE)
        self.assertTrue(web_tools.NUCLEI_STORE.startswith("/tmp/"))  # the memory-only tmpfs: the requests carry saved headers

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
        # Every certificate problem is one finding for the host, at the worst severity, with each check in its evidence.
        certificate = edge["certificate"]
        self.assertEqual(certificate["severity"], "critical")
        for check in ("cert_chain_of_trust: failed (self signed)", "cert_expirationStatus", "cert_revocation", "cert_trust", "cert_subjectAltName"):
            self.assertIn(check, certificate["web"]["evidence"])
        self.assertIn("6 certificate problems", text(certificate["title"], "en"))
        self.assertFalse({"cert_chain_of_trust", "cert_trust", "cert_expirationStatus", "cert_notAfter"} & set(edge))
        self.assertEqual(edge["HSTS"]["severity"], "low")
        self.assertEqual(edge["security_headers"]["severity"], "medium")
        self.assertFalse({"engine_problem", "scanTime", "service"} & set(edge))
        self.assertFalse(any(rule.startswith("cipher-") for rule in edge))
        self.assertEqual(web_tools.parse_testssl({"not": "a list"}, HOST), [])

    def test_testssl_ids_lose_their_certificate_suffix(self):
        # As testssl.sh 3.2 names them for pitangus.dev (two server certificates, two intermediates each); severities raised.
        document = [{"id": "cert_chain_of_trust <hostCert#1>", "severity": "CRITICAL", "finding": "failed (chain incomplete)."},
                    {"id": "cert_chain_of_trust <hostCert#2>", "severity": "OK", "finding": "passed."},
                    {"id": "intermediate_cert_expiration <#2> <hostCert#1>", "severity": "MEDIUM", "finding": "expires < 20 days"},
                    {"id": "cert_validityPeriod <hostCert#2>", "severity": "LOW", "finding": "398 days"},
                    {"id": "cipherlist_OBSOLETED <hostCert#1>", "severity": "LOW", "finding": "offered"},
                    {"id": "cipherlist_OBSOLETED <hostCert#2>", "severity": "LOW", "finding": "offered"},
                    {"id": "scanTime", "severity": "WARN", "finding": "60"}]
        self.assertEqual(web_tools.testssl_check("intermediate_cert_expiration <#2> <hostCert#1>"), ("intermediate_cert_expiration", "hostCert#1 #2"))
        found = {item["rule_id"]: item for item in web_tools.parse_testssl(document, HOST)}
        self.assertEqual(set(found), {"certificate", "cipherlist_OBSOLETED"})
        evidence = found["certificate"]["web"]["evidence"]
        self.assertIn("cert_chain_of_trust (hostCert#1): failed (chain incomplete).", evidence)
        self.assertIn("intermediate_cert_expiration (hostCert#1 #2): expires < 20 days", evidence)
        self.assertNotIn("<#", evidence)
        self.assertNotIn("<hostCert", evidence)
        self.assertEqual(found["certificate"]["severity"], "critical")
        self.assertIn("hostCert#2", found["cipherlist_OBSOLETED"]["web"]["evidence"])

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
        self.assertEqual(web_tools.nuclei_log('{"percent":"0","requests":"0","total":"27"}\n', [HOST]), (set(), True))  # nothing sent
        # A finished host pass on pitangus.dev (2,398 templates): 99% and 16 request errors, nothing skipped, is complete.
        self.assertEqual(web_tools.nuclei_log(fixture("nuclei-3.11-hosts.log"), [HOST]), (set(), False))
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

    def test_testssl_header_summary_and_certificate_family_fold_into_the_other_tools_findings(self):
        csp = finding("ZAP", "10038", f"https://{HOST}/", "medium")
        frame = finding("ZAP", "10020", f"https://{HOST}/", "medium")
        headers = finding("testssl", "security_headers", f"https://{HOST}/", "medium", web={"evidence": "--"})
        merged, folded = web_merge.merge([headers, frame, csp])
        self.assertEqual((len(merged), folded), (2, 1))
        self.assertEqual(next(item for item in merged if item["rule_id"] == "10038")["also_detected_by"], ["testssl"])
        alone, folded = web_merge.merge([finding("testssl", "security_headers", f"https://{HOST}/")])
        self.assertEqual((len(alone), folded), (1, 0))  # nothing to fold into: it stays, as testssl.sh's
        nuclei = finding("nuclei", "self-signed-ssl", f"https://{HOST}/", "medium")
        certificate = finding("testssl", "certificate", f"https://{HOST}", "critical", web={"evidence": "cert_chain_of_trust: failed"})
        (only,), folded = web_merge.merge([certificate, nuclei])
        self.assertEqual((only["fingerprint"], only["severity"], folded), (nuclei["fingerprint"], "critical", 1))
        self.assertEqual(only["web"]["also"][0]["evidence"], "cert_chain_of_trust: failed")

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
        self.assertEqual(web_merge.family_of(finding("testssl", "certificate", f"https://{HOST}/")),
                         web_merge.family_of(finding("nuclei", "self-signed-ssl", f"https://{HOST}/")))
        self.assertIsNone(web_merge.family_of(finding("nuclei", "HSTS", f"https://{HOST}/")))  # a rule counts for its own tool only
        for family, tools in web_merge.EQUIVALENT.items():
            with self.subTest(family=family):
                self.assertGreaterEqual(len(tools), 2)
                self.assertTrue(set(tools) <= set(web_merge.ORDER))


def fake_site(files: dict[str, str], requested: list | None = None):
    """`domains.https_get` answering the scan's robots.txt and sitemap requests from `files` (path → body), 404 otherwise."""
    def get(host, address, path, *, limit, seconds):
        if requested is not None:
            requested.append((host, address, path))
        body = files.get(path)
        return (200, body.encode()) if body is not None else (404, b"")
    return patch("pitangus.modules.sources.domains.https_get", side_effect=get)


class PipelineTests(unittest.TestCase):
    """katana → robots.txt and sitemaps → ZAP (with the inventory) → nuclei over everything → testssl.sh → httpx."""

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
                        "testssl": fixture("testssl-3.2.json"),
                        "zap_urls": fixture("zap-2.17-urls.txt") + "https://evil.example/x\nnot a url\n"}
        self.site = {"/robots.txt": fixture("robots-pitangus.dev.txt"), "/sitemap.xml": fixture("sitemap-pitangus.dev.xml")}
        self.requested: list = []

    def scan(self, *, ready=None, **options):
        calls, inputs = [], []
        with fake_tools(self.outputs, calls=calls, **options), fake_site(self.site, self.requested):
            result = web.scan_domain(self.record, PINS["pitangus.dev"], data_dir=self.data_dir, tools=ready or dict.fromkeys(web_tools.TOOLS),
                                     progress=lambda level, message: inputs.append((level, text(message, "en"))))
        return result, calls, inputs

    def test_every_tool_runs_in_order_and_reports_its_step(self):
        result, calls, progress = self.scan()
        # The crawl found /es/: nuclei's page-level pass reads it, after the pass on the host's root.
        # httpx twice: the roots' technologies, then the status of every page reached.
        self.assertEqual([key for key, _, _ in calls], ["katana", "zap", "nuclei", "nuclei", "testssl", "httpx", "httpx"])
        steps = [(step["id"], step["status"]) for step in result["steps"]]
        self.assertEqual(steps, [("dast-katana", "completed"), ("dast", "completed"), ("dast-inventory", "completed"), ("dast-nuclei", "completed"),
                                 ("dast-testssl", "completed"), ("dast-httpx", "completed"), ("dast-versions", "completed"), ("dast-merge", "completed"),
                                 ("active", "not_tested"),
                                 ("review", "pending")])
        self.assertEqual(result["status"], "completed")
        inventory = result["web_inventory"]
        self.assertIn(f"https://{HOST}/", inventory["urls"])
        self.assertIn(f"https://{HOST}/es/", inventory["urls"])
        self.assertIn(f"https://{HOST}/robots.txt", inventory["urls"])  # only ZAP's spider had it
        self.assertEqual(inventory["count"], len(inventory["urls"]))
        self.assertEqual((inventory["sources"]["robots"], inventory["sources"]["sitemap"]), (0, 0))  # katana had them all
        self.assertIn(f"https://{HOST}/sitemap.xml", inventory["urls"])
        self.assertGreater(inventory["sources"]["zap"], 10)  # the fonts, images and files only the spider requested
        self.assertTrue(all(url.startswith(f"https://{HOST}/") and "?" not in url for url in inventory["urls"]))
        # robots.txt and the sitemap were asked from the pinned address, before ZAP.
        self.assertEqual(self.requested, [(HOST, PINS[HOST], "/robots.txt"), (HOST, PINS[HOST], "/sitemap.xml")])
        pages = next(given for key, command, given in calls if key == "nuclei" and "/templates/pages" in command)
        self.assertIsNone(pages)
        nuclei_pages = [command for key, command, _ in calls if key == "nuclei" and "/templates/pages" in command]
        self.assertEqual(len(nuclei_pages), 1)
        step = next(step for step in result["steps"] if step["id"] == "dast-inventory")
        self.assertIn("from the sitemaps", text(step["detail"], "en"))
        self.assertTrue({"ZAP", "nuclei", "testssl"} <= {item["tool"] for item in result["findings"]})
        self.assertTrue(all(item["web"]["coverage"] == "baseline" for item in result["findings"]))
        # The kind of scan stays the scope's coverage key; what each tool examined, page by page, goes apart.
        self.assertEqual(result["scope"]["coverage"], "baseline")
        self.assertIn(f"https://{HOST}/", result["coverage"]["zap"]["examined"])  # httpx's status pass saw it answer 200
        self.assertIn(f"https://{HOST}/es", result["coverage"]["zap"]["examined"])

        self.assertIn("Cloudflare", {row["name"] for row in result["summary"]["technologies"]})
        self.assertEqual({tool["name"]: tool["status"] for tool in result["summary"]["tools"]},
                         {"ZAP": "completed", "katana": "completed", "nuclei": "completed", "testssl": "completed", "httpx": "completed",
                          "httpx + OSV": "completed"})
        # ZAP got katana's URLs to request before its spider (other than where the spider starts).
        plan = json.loads(calls[1][2])
        self.assertEqual(plan["jobs"][1], {"type": "import", "parameters": {"type": "url", "fileName": f"{web.WORK}/{web.SEEDS}"}})
        self.assertTrue(any("katana" in line for _, line in progress))


    def test_only_zaps_own_answer_vouches_for_a_zap_finding(self):
        """ZAP got 429 on /es/ and a 302 on the root; katana and httpx got 200 there: neither page is ZAP's to vouch for."""
        self.outputs["zap_statuses"] = {f"https://{HOST}/es/": 429, f"https://{HOST}/": 302}
        result, _, _ = self.scan()
        examined, unexamined = result["coverage"]["zap"]["examined"], result["coverage"]["zap"]["unexamined"]
        self.assertNotIn(f"https://{HOST}/es", examined)
        self.assertNotIn(f"https://{HOST}/", examined)
        self.assertEqual((unexamined[f"https://{HOST}/es"], unexamined[f"https://{HOST}/"]), ("http_429", "http_302"))
        self.assertEqual(result["scope"]["reached"], examined)
        self.assertTrue(examined)

    def test_a_page_that_redirects_or_fails_is_not_examined(self):
        self.outputs["statuses"] = {f"https://{HOST}/es/": 302, f"https://{HOST}/": 503}
        result, calls, _ = self.scan()
        examined = result["coverage"]["zap"]["examined"]
        self.assertNotIn(f"https://{HOST}/es", examined)  # a redirect (to a login, say) isn't the page
        self.assertNotIn(f"https://{HOST}/", examined)
        pages = next(command for key, command, _ in calls if key == "httpx" and f"{web_tools.WORK}/pages.txt" in command)
        self.assertNotIn("-fhr", pages)  # the status pass follows no redirect

    def test_a_waf_that_turns_the_crawl_away_leaves_the_scan_incomplete(self):
        refused = "".join(json.dumps({"request": {"method": "GET", "endpoint": f"https://{HOST}/{page}"}, "response": {"status_code": code}}) + "\n"
                          for page, code in (("", 403), ("es/", 403), ("blog/", 429), ("about/", 403), ("cdn-cgi/l", 200),
                                             *((f"blog/{index}/", 403) for index in range(8))))
        blocked = web.engine_contract.blocked_hosts
        self.assertEqual(blocked({"katana": [(HOST, status) for _, status in web_tools.katana_answers(refused, [HOST])]}), [HOST])
        ordinary = web_tools.katana_answers(fixture("katana-1.7.jsonl"), [HOST])
        self.assertEqual(blocked({"katana": [(HOST, status) for _, status in ordinary]}), [])  # an ordinary crawl
        self.outputs["katana"] = refused
        result, _, _ = self.scan()
        katana = next(step for step in result["steps"] if step["id"] == "dast-katana")
        self.assertEqual((katana["status"], result["status"]), ("partial", "incomplete"))
        self.assertIn("turned the scan away", " ".join(text(item, "en") for item in result["limitations"]))

    def test_a_failing_tool_leaves_its_step_partial_and_the_scan_goes_on(self):
        result, calls, _ = self.scan(returncodes={"httpx": 1}, raising={"nuclei": subprocess.TimeoutExpired(["docker"], 60), "katana": OSError("boom")})
        statuses = {step["id"]: step["status"] for step in result["steps"]}
        self.assertEqual((statuses["dast-katana"], statuses["dast-nuclei"], statuses["dast-httpx"], statuses["dast"]),
                         ("partial", "partial", "partial", "completed"))
        self.assertEqual(result["status"], "completed")  # ZAP finished: the partial tools are in the steps and the limitations
        self.assertEqual({tool["name"]: tool["status"] for tool in result["summary"]["tools"]}["nuclei"], "inconclusive")
        limitations = " ".join(text(item, "en") for item in result["limitations"])
        self.assertIn("nuclei didn't finish", limitations)
        # Without katana, the sitemap's /es/ still reaches ZAP; with neither, ZAP gets no list to import.
        self.assertIn("import", [job["type"] for job in json.loads(next(given for key, _, given in calls if key == "zap"))["jobs"]])
        self.site = {}
        _, calls, _ = self.scan(raising={"katana": OSError("boom")})
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


class LogoutTests(unittest.TestCase):
    """A crawl carrying a session never follows a sign-out link: it would scan the rest anonymously."""

    def test_sign_out_links_are_left_out_of_both_crawlers(self):
        import re
        from pitangus.modules.scanning import web, web_tools
        for url in ("https://app.example.com/logout", "https://app.example.com/auth/sign-out?next=/", "https://app.example.com/LogOff.aspx"):
            self.assertTrue(re.fullmatch(web_tools.LOGOUT_ZAP, url), url)
            self.assertTrue(re.search(web_tools.LOGOUT, url), url)
        self.assertIsNone(re.search(web_tools.LOGOUT, "https://app.example.com/blog/logouts-explained"))
        self.assertIn(web_tools.LOGOUT, web_tools.katana_arguments(["app.example.com"], headless=False))
        anonymous = web.plan("app.example.com", "https://app.example.com/")
        with_headers = web.plan("app.example.com", "https://app.example.com/", headers=[("Authorization", "Bearer x")])
        self.assertNotIn("excludePaths", anonymous["env"]["contexts"][0])
        self.assertEqual(with_headers["env"]["contexts"][0]["excludePaths"], [web_tools.LOGOUT_ZAP])


class WebIdentityTests(unittest.TestCase):
    """A header of the whole site is one finding per host; a hashed asset keeps its identity across deploys."""

    def test_site_level_alerts_and_hashed_names(self):
        from pitangus.modules.scanning import web_identity as identity
        self.assertTrue(identity.site_level("ZAP", "10055-6"))
        self.assertTrue(identity.site_level("nuclei", "http-missing-security-headers:content-security-policy"))
        self.assertFalse(identity.site_level("ZAP", "10096"))
        self.assertEqual(identity.root_of("https://Pitangus.dev/blog/post-1?x=1"), "https://pitangus.dev/")
        for before, after in (("https://h/_astro/CSY8UEx1.js", "https://h/_astro/*.js"), ("https://h/assets/index-BkL9x2a1.css", "https://h/assets/index-*.css"),
                              ("https://h/js/app.3f2a9b1c.js", "https://h/js/app.*.js"), ("https://h/_astro/Base.astro.CCbp9-6k.js", "https://h/_astro/Base.astro.*.js"), ("https://h/js/bootstrap5.js", "https://h/js/bootstrap5.js"),
                              ("https://h/js/jquery-3.6.0.min.js", "https://h/js/jquery-3.6.0.min.js"), ("https://h/about/", "https://h/about/")):
            self.assertEqual(identity.identity_path(before), after, before)

    def test_the_same_comment_on_every_page_is_one_finding_and_another_comment_another(self):
        from pitangus.modules.scanning import sarif_import

        def result(page, comment):
            return {"ruleId": "10027", "level": "note", "message": {"text": "Suspicious comment"},
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": f"https://{EDGE}/{page}"},
                                                        "region": {"snippet": {"text": comment}}}}]}
        layout, missing = "<!-- TODO: remove the debug panel -->", "-- The 404 template's note"
        document = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "ZAP", "rules": [{"id": "10027"}]}},
                                                  "results": [result(page, layout) for page in ("", "blog/", "about/")]
                                                  + [result("missing", missing), result("gone", missing)]}]}
        findings = sarif_import.parse(document)[0]["findings"]
        self.assertEqual([item["path"] for item in findings], [f"https://{EDGE}/", f"https://{EDGE}/"])
        # Every page's former fingerprint, the root's too: it was keyed without the evidence.
        self.assertEqual([len(item["previous_fingerprints"]) for item in findings], [3, 2])

    def test_missing_headers_on_every_page_are_one_finding_per_host(self):
        lines = "".join(json.dumps({"template-id": "http-missing-security-headers", "matcher-name": "content-security-policy",
                                    "info": {"name": "HTTP Missing Security Headers", "severity": "info", "tags": ["misconfig", "headers"]},
                                    "matched-at": f"https://{EDGE}/{page}", "host": EDGE, "type": "http"}) + "\n" for page in ("", "blog/a", "about/"))
        findings, _ = web_tools.parse_nuclei(lines, [EDGE])
        self.assertEqual([item["path"] for item in findings], [f"https://{EDGE}/"])
        # Each page's former fingerprint goes with it, so the per-page findings stored before fold into this one.
        former = lambda page: engines._stable("sarif", "nuclei", "\x1f".join(("http-missing-security-headers:content-security-policy", page, "")))  # noqa: E731
        self.assertEqual(findings[0]["previous_fingerprints"], [former(f"https://{EDGE}/blog/a"), former(f"https://{EDGE}/about/")])


class ExposureTests(PipelineTests):
    """The light exposure check: roots and known paths, no crawl, the same rules as a full scan."""

    def exposure(self, **options):
        calls, inputs = [], []
        with fake_tools(self.outputs, calls=calls, **options):
            result = web.scan_exposure(self.record, PINS["pitangus.dev"], data_dir=self.data_dir, tools=dict.fromkeys(web_tools.TOOLS),
                                       recheck=[f"https://{HOST}/old/config.php", "https://evil.example/x"],
                                       progress=lambda level, message: inputs.append((level, text(message, "en"))))
        return result, calls

    def test_no_crawl_no_zap_and_every_known_path_checked(self):
        self.outputs["statuses"] = {f"https://{HOST}/.aws/credentials": 404, f"http://{HOST}/.aws/credentials": 410}
        result, calls = self.exposure()
        self.assertNotIn("katana", [key for key, _, _ in calls])
        self.assertNotIn("zap", [key for key, _, _ in calls])
        pages = next(command for key, command, _ in calls if key == "httpx" and f"{web_tools.WORK}/pages.txt" in command)
        self.assertTrue(pages)
        self.assertEqual((result["variant"], result["scope"]["coverage"], result["status"]), ("exposure", "exposure", "completed"))
        self.assertTrue(all(item["web"]["coverage"] == "exposure" for item in result["findings"]))
        examined = result["coverage"]["nuclei"]["examined"]
        self.assertIn(f"https://{HOST}/.aws/credentials", examined)  # a known path nuclei's own requests found gone
        self.assertIn(f"http://{HOST}/.aws/credentials", examined)   # plain HTTP on port 80 too
        self.assertEqual(result["coverage"]["nuclei"]["unexamined"][f"https://{HOST}/.env"], "present")  # still answers 200
        self.assertNotIn(f"https://{HOST}/old/config.php", examined)  # httpx checks it again; nuclei never asked for it
        self.assertIn(f"https://{HOST}/old/config.php", self.outputs["checked"])
        self.assertFalse(any("evil.example" in page for page in examined))

    def test_a_404_on_a_known_path_is_examined_and_a_waf_leaves_it_incomplete(self):
        self.outputs["statuses"] = {f"https://{HOST}/.aws/credentials": 404}
        result, _ = self.exposure()
        self.assertIn(f"https://{HOST}/.aws/credentials", result["coverage"]["nuclei"]["examined"])
        paths = [f"https://{HOST}/", *(f"https://{HOST}{path}" for path in web.known_paths())]
        self.outputs["statuses"] = dict.fromkeys(paths, 403)
        blocked, _ = self.exposure()
        self.assertEqual(blocked["status"], "incomplete")
        self.assertFalse(any(page.startswith(f"https://{HOST}/.") for page in blocked["coverage"]["nuclei"]["examined"]))

    def test_known_paths_come_from_the_templates(self):
        paths = web.known_paths()
        self.assertIn("/.aws/credentials", paths)
        self.assertTrue(all(path.startswith("/") and "{{" not in path for path in paths))

