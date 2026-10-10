"""Pitangus' own nuclei templates (pitangus/modules/scanning/rules/nuclei): they pass the same filter as the release's,
only read, prove what they report with the response's content, and carry their text in English and Spanish.

The matchers are checked here against small responses with a reduced evaluator of nuclei's matcher semantics (status,
word, regex, binary; `part`, `condition`, `negative`, `matchers-condition`); nuclei 3.11 itself validated them and
matched the same positives (and none of the negatives) against a throwaway local site when they were written."""

import json
import re
import tempfile
import unittest
from pathlib import Path

import yaml

from pitangus.modules.scanning import nuclei_templates, web_tools
from pitangus.shared.i18n import text

ROOT = nuclei_templates.OWN
HOST = "pitangus.dev"


def templates() -> dict[str, tuple[str, dict]]:
    return {document["id"]: (relative, document) for relative, data in nuclei_templates.own_templates()
            for document in [yaml.safe_load(data)]}


def response(body: str | bytes = "", *, status: int = 200, content_type: str = "text/html; charset=utf-8") -> dict:
    return {"status": status, "header": f"HTTP/1.1 {status} OK\r\nContent-Type: {content_type}\r\n",
            "body": body if isinstance(body, bytes) else body.encode()}


def _matches(matcher: dict, answer: dict) -> bool:
    part = matcher.get("part", "body")
    raw = answer["header"].encode() + b"\r\n" + answer["body"] if part == "all" else answer["header"].encode() if part == "header" else answer["body"]
    content = raw.decode("utf-8", "replace")
    kind = matcher["type"]
    if kind == "status":
        results = [answer["status"] in matcher["status"]]
    elif kind == "word":
        results = [word in content for word in matcher["words"]]
    elif kind == "regex":
        results = [re.search(pattern, content) is not None for pattern in matcher["regex"]]
    elif kind == "binary":
        results = [bytes.fromhex(value) in raw for value in matcher["binary"]]
    else:
        raise AssertionError(f"matcher type {kind} isn't evaluated here")
    found = all(results) if matcher.get("condition", "or") == "and" else any(results)
    return not found if matcher.get("negative") else found


def evaluate(request: dict, answer: dict) -> tuple[bool, list[str]]:
    """Whether one request block of a template matches `answer`, and the names of the matchers that did."""
    outcomes = [(matcher, _matches(matcher, answer)) for matcher in request["matchers"]]
    if request.get("matchers-condition", "or") == "and":
        matched = all(result for _, result in outcomes)
    else:
        matched = any(result for _, result in outcomes)
    return matched, [matcher["name"] for matcher, result in outcomes if result and matcher.get("name") and not matcher.get("negative")]


def block(document: dict, name: str) -> dict:
    return next(request for request in document["http"] if any(matcher.get("name") == name for matcher in request["matchers"]))


class FilterTests(unittest.TestCase):
    def test_every_own_template_passes_the_release_filter_and_only_reads(self):
        found = templates()
        self.assertEqual(set(found), {"pitangus-directory-listing", "pitangus-json-credentials", "pitangus-sensitive-paths",
                                      "pitangus-api-description", "pitangus-metadata-files", "pitangus-security-txt"})
        for template, (relative, document) in found.items():
            with self.subTest(template=template):
                self.assertTrue(nuclei_templates.allowed(relative, document))
                self.assertIsNotNone(nuclei_templates.own_allowed(relative, yaml.safe_dump(document).encode()))
                self.assertFalse(nuclei_templates.DENY_TAGS & nuclei_templates._tags(document))
                requests = document["http"]
                total = 0
                for request in requests:
                    self.assertEqual(request.get("method", "GET"), "GET")
                    self.assertNotIn("payloads", request)
                    self.assertNotIn("raw", request)
                    for path in request["path"]:
                        self.assertTrue(path.startswith("{{BaseURL}}"), path)
                        self.assertNotIn("?", path)
                        self.assertIsNone(nuclei_templates.STATE.search(path), path)
                        total += 1
                    # Every check proves content: a status code alone never matches.
                    self.assertTrue(any(matcher["type"] != "status" and not matcher.get("negative") for matcher in request["matchers"]))
                self.assertLessEqual(total, nuclei_templates.PAYLOAD_MAX)
                self.assertEqual(document["info"]["metadata"]["max-request"], total)

    def test_each_template_names_its_weakness_its_references_and_what_to_do_in_both_languages(self):
        for template, (_, document) in templates().items():
            info = document["info"]
            with self.subTest(template=template):
                self.assertTrue(template.startswith(nuclei_templates.OWN_PREFIX))
                self.assertIn(info["severity"], ("info", "low", "medium", "high", "critical"))
                references = info["reference"]
                self.assertTrue(references and all(url.startswith("https://") for url in references))
                self.assertTrue(any(re.match(r"https://(?:owasp\.org/www-project-web-security-testing-guide/|cheatsheetseries\.owasp\.org/)", url)
                                    for url in references))
                if "tech" in nuclei_templates._tags(document):
                    continue  # a fact shown with the technologies, not a finding
                self.assertRegex(str(info["classification"]["cwe-id"]), r"^CWE-\d+(?:,CWE-\d+)*$")
                for field in ("name", "description", "remediation"):
                    self.assertTrue(str(info[field]).strip())
                    self.assertTrue(str(info["metadata"][f"pitangus-{field}-es"]).strip())
                self.assertIn("OWASP", info["remediation"])

    def test_the_sensitive_paths_template_reads_a_short_fixed_list_on_each_host(self):
        _, document = templates()["pitangus-sensitive-paths"]
        paths = [path.removeprefix("{{BaseURL}}") for request in document["http"] for path in request["path"]]
        self.assertLessEqual(len(paths), 60)
        self.assertEqual(len(paths), len(set(paths)))
        for expected in ("/ftp/", "/backup/", "/backups/", "/config/", "/metrics", "/actuator", "/actuator/env", "/server-status", "/phpinfo.php"):
            self.assertIn(expected, paths)
        # /uploads/ names a state change for the filter (`upload`), so it can't be in a template that passes it.
        self.assertIsNotNone(nuclei_templates.STATE.search("/uploads/"))
        self.assertFalse(nuclei_templates.page_level(document))

    def test_own_templates_are_built_next_to_the_release_split_in_hosts_and_pages(self):
        with tempfile.TemporaryDirectory() as directory:
            folder, counts = nuclei_templates.ensure_own(Path(directory))
            self.assertIsNotNone(folder)
            assert folder is not None
            self.assertTrue(folder.name.startswith("pitangus-"))
            self.assertEqual(counts, {"hosts": 6, "pages": 2})
            pages = sorted(path.name for path in (folder / "pages").rglob("*.yaml"))
            self.assertEqual(pages, ["pitangus-directory-listing.yaml", "pitangus-json-credentials.yaml"])
            self.assertEqual(nuclei_templates.ensure_own(Path(directory)), (folder, counts))  # built once
            # A template that doesn't pass the filter (a POST) never reaches the folder.
            extra = Path(directory) / "own"
            (extra / "http" / "exposures").mkdir(parents=True)
            bad = {"id": "pitangus-bad", "info": {"name": "x", "severity": "low"},
                   "http": [{"method": "POST", "path": ["{{BaseURL}}/x"], "matchers": [{"type": "word", "words": ["x"]}]}]}
            (extra / "http" / "exposures" / "pitangus-bad.yaml").write_text(yaml.safe_dump(bad))
            other, other_counts = nuclei_templates.ensure_own(Path(directory) / "cache", root=extra)
            self.assertEqual(other_counts, {"hosts": 0, "pages": 0})
            assert other is not None
            self.assertEqual(list((other).rglob("*.yaml")), [])

    def test_nuclei_gets_them_read_only_next_to_the_release(self):
        arguments = web_tools.nuclei_arguments("pages", 3, own=True)
        targets = [arguments[index + 1] for index, item in enumerate(arguments) if item == "-t"]
        self.assertEqual(targets, ["/templates/pages", f"{web_tools.OWN_MOUNT}/pages"])


DIRECTORY_LISTING = """<!DOCTYPE HTML><html lang="en"><head><meta charset="utf-8"><title>Directory listing for /ftp/</title></head>
<body><h1>Directory listing for /ftp/</h1><hr><ul><li><a href="a.txt">a.txt</a></li></ul><hr></body></html>"""
APACHE_LISTING = "<html><head><title>Index of /backup</title></head><body><h1>Index of /backup</h1><pre>db.sql</pre></body></html>"
NOT_FOUND = "<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1></body></html>"


class MatcherTests(unittest.TestCase):
    def setUp(self):
        self.found = templates()

    def check(self, template: str, request: dict, positives: list[dict], negatives: list[dict]):
        for index, answer in enumerate(positives):
            with self.subTest(template=template, positive=index):
                self.assertTrue(evaluate(request, answer)[0])
        for index, answer in enumerate(negatives):
            with self.subTest(template=template, negative=index):
                self.assertFalse(evaluate(request, answer)[0])

    def test_directory_listing(self):
        (request,) = self.found["pitangus-directory-listing"][1]["http"]
        self.check("pitangus-directory-listing", request,
                   [response(DIRECTORY_LISTING), response(APACHE_LISTING), response("<title>listing directory /ftp</title>")],
                   [response(NOT_FOUND), response(DIRECTORY_LISTING, status=403),
                    response('{"title": "Index of /"}', content_type="application/json"),
                    response("<html><title>Docs</title><p>The index of /api endpoints</p></html>")])

    def test_credentials_in_json(self):
        (request,) = self.found["pitangus-json-credentials"][1]["http"]
        json_type = "application/json; charset=utf-8"
        self.check("pitangus-json-credentials", request,
                   [response('{"id": 1, "password": "Hunter2024!"}', content_type=json_type),
                    response('{"config": {"api_key": "sk_live_51HxYz9AbCdEf"}}', content_type=json_type),
                    response('{"Token":"eyJhbGciOiJIUzI1NiJ9.e30.abc"}', content_type="application/problem+json")],
                   [response('{"password": "string", "token": "YOUR_API_TOKEN", "secret": "", "api_key": "********"}', content_type=json_type),
                    response('{"password": null, "token": "<token>", "secret": "{{secret}}"}', content_type=json_type),
                    response('{"$schema": "http://json-schema.org/draft-07/schema#", "example": {"password": "Hunter2024!"}}', content_type=json_type),
                    response('{"openapi": "3.0.3", "components": {"examples": {"password": "Hunter2024!"}}}', content_type=json_type),
                    response('{"type": "object", "properties": {"password": {"default": "Hunter2024!"}}}', content_type=json_type),
                    response('{"password_hint": "min 8 chars", "passwordLength": "12345678"}', content_type=json_type),
                    response('{"password": "Hunter2024!"}', content_type="text/html"),
                    response('{"password": "Hunter2024!"}', status=404, content_type=json_type)])

    def test_sensitive_paths(self):
        document = self.found["pitangus-sensitive-paths"][1]
        cases = {
            "directory-listing": (response(DIRECTORY_LISTING), response(NOT_FOUND)),
            "prometheus-metrics": (response("# HELP up Up\n# TYPE up gauge\nup 1\n", content_type="text/plain"),
                                   response("<html># HELP is here</html>")),
            "spring-actuator": (response('{"_links":{"self":{"href":"https://x/actuator","templated":false},"env":{"href":"https://x/actuator/env"}}}'),
                                response('{"_links":{"self":{"href":"https://x/api"}}}')),
            "spring-actuator-env": (response('{"activeProfiles":["prod"],"propertySources":[]}'), response('{"profiles": "none"}')),
            "spring-actuator-configprops": (response('{"contexts":{"app":{"beans":{}}}}'), response('{"contexts":{}}')),
            "spring-actuator-mappings": (response('{"contexts":{"app":{"mappings":{"dispatcherServlets":{}}}}}'), response("{}")),
            "apache-server-status": (response("<h1>Apache Server Status for example.org (via 10.0.0.1)</h1>"), response(NOT_FOUND)),
            "apache-server-info": (response("<h1>Apache Server Information</h1>"), response(NOT_FOUND)),
            "phpinfo": (response("<html><head><title>PHP 8.3.1 - phpinfo()</title></head></html>"), response("<title>About PHP</title>")),
            "go-pprof": (response("<p>Types of profiles available:</p>"), response(NOT_FOUND)),
            "elmah": (response("<title>Error log for /LM/W3SVC on SRV - ELMAH</title>"), response(NOT_FOUND)),
            "aspnet-trace": (response("<h1>Application Trace</h1>"), response(NOT_FOUND)),
            "werkzeug-console": (response("<title>Console // Werkzeug Debugger</title>"), response("<title>Console</title>")),
            "htpasswd": (response("admin:$apr1$abc$def\n", content_type="text/plain"), response("admin:secret\n", content_type="text/plain")),
            "npmrc-token": (response("//registry.npmjs.org/:_authToken=npm_abcdefghij123\n", content_type="text/plain"),
                            response("registry=https://registry.npmjs.org/\n", content_type="text/plain")),
            "aws-credentials": (response("[default]\naws_access_key_id = AKIA\naws_secret_access_key = abc\n", content_type="text/plain"),
                                response("[default]\nregion = us-east-1\n", content_type="text/plain")),
            "docker-credentials": (response('{"auths": {"ghcr.io": {"auth": "dXNlcjpwYXNzd29yZA=="}}}'), response('{"auths": {}}')),
            "wordpress-config-backup": (response("<?php\ndefine( 'DB_PASSWORD', 'x' );\n", content_type="application/octet-stream"),
                                        response("<?php\n// nothing\n", content_type="application/octet-stream")),
        }
        named = {matcher["name"] for request in document["http"] for matcher in request["matchers"] if matcher.get("name")}
        self.assertEqual(named, set(cases))
        for name, (positive, negative) in cases.items():
            request = block(document, name)
            with self.subTest(matcher=name):
                self.assertEqual(evaluate(request, positive), (True, [name]))
                self.assertFalse(evaluate(request, negative)[0])

    def test_api_description(self):
        document = self.found["pitangus-api-description"][1]
        definition = block(document, "openapi-definition")
        self.check("openapi-definition", definition,
                   [response('{"openapi": "3.1.0", "info": {}, "paths": {"/a": {}}}', content_type="application/json"),
                    response('{"swagger":"2.0","paths":{}}', content_type="application/json")],
                   [response('{"openapi": "maybe", "paths": {}}'), response(NOT_FOUND)])
        yaml_definition = next(request for request in document["http"] if request["path"] == ["{{BaseURL}}/openapi.yaml"])
        self.check("openapi-yaml", yaml_definition, [response("openapi: 3.0.3\ninfo:\n  title: x\npaths:\n  /a: {}\n")],
                   [response("title: openapi 3\n")])
        self.check("swagger-ui", block(document, "swagger-ui"), [response("<html><head><title>Swagger UI</title></head></html>")],
                   [response(NOT_FOUND)])

    def test_metadata_files(self):
        document = self.found["pitangus-metadata-files"][1]
        self.check("ds-store", block(document, "ds-store"), [response(b"\x00\x00\x00\x01Bud1" + b"\x00" * 16, content_type="application/octet-stream")],
                   [response(NOT_FOUND)])
        self.check("gitignore", block(document, "gitignore"), [response("node_modules/\n*.log\n.env\n", content_type="text/plain")],
                   [response("<!DOCTYPE html><html><pre>\nnode_modules/\n</pre></html>"), response("hello\n", content_type="text/plain")])
        self.check("idea-workspace", block(document, "idea-workspace"),
                   [response('<?xml version="1.0"?>\n<project version="4">\n  <component name="ChangeListManager">', content_type="application/xml")],
                   [response("<project></project>", content_type="application/xml")])
        self.check("mercurial-config", block(document, "mercurial-config"), [response("[paths]\ndefault = https://hg.example/x\n", content_type="text/plain")],
                   [response("<html>[paths]\n</html>")])

    def test_security_txt_is_a_fact(self):
        _, document = self.found["pitangus-security-txt"]
        (request,) = document["http"]
        self.check("pitangus-security-txt", request, [response("Contact: mailto:security@example.org\nExpires: 2027-01-01T00:00:00Z\n", content_type="text/plain")],
                   [response("<!DOCTYPE html><html><p>Contact: us</p></html>"), response("Hello\n", content_type="text/plain")])
        line = json.dumps({"template-id": "pitangus-security-txt", "template-path": f"{web_tools.OWN_MOUNT}/hosts/http/technologies/pitangus-security-txt.yaml",
                           "info": {"name": "security.txt", "severity": "info", "tags": ["tech", "discovery", "pitangus"]},
                           "matched-at": f"https://{HOST}/.well-known/security.txt"})
        findings, technologies = web_tools.parse_nuclei(line, [HOST])
        self.assertEqual((findings, technologies), ([], [{"name": "security.txt", "version": None, "host": HOST}]))


class ParserTests(unittest.TestCase):
    def line(self, path: str, **extra) -> str:
        _, document = templates()["pitangus-sensitive-paths"]
        info = {key: document["info"][key] for key in ("name", "severity", "description", "remediation", "reference", "metadata")}
        info["tags"] = document["info"]["tags"].split(",")
        info["classification"] = {"cwe-id": ["cwe-200", "cwe-538"]}
        return json.dumps({"template-id": "pitangus-sensitive-paths", "template-path": path, "info": info, "matcher-name": "spring-actuator-env",
                           "matched-at": f"https://{HOST}/actuator/env", "type": "http", **extra})

    def test_own_findings_speak_both_languages_and_keep_their_remediation(self):
        (finding,), _ = web_tools.parse_nuclei(self.line(f"{web_tools.OWN_MOUNT}/hosts/http/exposures/pitangus-sensitive-paths.yaml"), [HOST])
        self.assertEqual(finding["rule_id"], "pitangus-sensitive-paths:spring-actuator-env")
        self.assertEqual(text(finding["title"], "en"), "Sensitive file or endpoint exposed (spring-actuator-env)")
        self.assertEqual(text(finding["title"], "es"), "Archivo o endpoint sensible expuesto (spring-actuator-env)")
        self.assertTrue(text(finding["remediation"], "es").startswith("Quita el archivo"))
        self.assertTrue(text(finding["remediation"], "en").startswith("Remove the file"))
        self.assertIn("datos internos", text(finding["web"]["description"], "es"))
        self.assertEqual((finding["cwe"], finding["severity"], finding["path"]), ([200, 538], "medium", f"https://{HOST}/actuator/env"))
        self.assertTrue(all(url.startswith("https://owasp.org/") for url in finding["web"]["references"]))

    def test_a_release_template_named_like_ours_keeps_its_text_as_published(self):
        (finding,), _ = web_tools.parse_nuclei(self.line("/templates/hosts/http/exposures/pitangus-sensitive-paths.yaml"), [HOST])
        self.assertIsInstance(finding["title"], str)
        self.assertIn("nuclei", text(finding["remediation"], "en"))


if __name__ == "__main__":
    unittest.main()
