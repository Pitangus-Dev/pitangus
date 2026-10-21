"""OpenAPI definitions for the passive API scan: read without trusting them, reduced to what a passive scan may send."""

import json
import unittest

from pitangus.modules.scanning import openapi_spec
from pitangus.modules.scanning.openapi_spec import SpecError
from pitangus.shared.i18n import text

HOST = "pitangus.dev"
YAML = b"""openapi: 3.1.0
info:
  title: Agenda
  version: '1'
servers:
  - url: https://api.pitangus.dev/v2
webhooks:
  booked: {post: {responses: {'200': {description: ok}}}}
paths:
  /slots:
    get:
      parameters: [{name: day, in: query, schema: {type: string, format: date}, example: 2026-10-10}]
      responses: {'200': {description: ok}}
    post:
      responses: {'201': {description: created}}
  /slots/{id}:
    servers: [{url: 'https://evil.example'}]
    put: {responses: {'200': {description: ok}}}
    patch: {responses: {'200': {description: ok}}}
    delete: {responses: {'204': {description: gone}}}
  /health:
    head: {responses: {'200': {description: ok}}}
    options: {responses: {'200': {description: ok}}}
    trace: {responses: {'200': {description: ok}}}
"""


def error(raw: bytes, filename: str = "") -> str:
    with unittest.TestCase().assertRaises(SpecError) as caught:
        openapi_spec.parse(raw, filename)
    return text(caught.exception.message, "en")


class ParseTests(unittest.TestCase):
    def test_only_get_and_head_operations_survive_and_nothing_points_elsewhere(self):
        parsed = openapi_spec.parse(YAML, "agenda.yaml")
        self.assertEqual((parsed["endpoints"], parsed["version"], parsed["server"]), (2, "3.1.0", {"host": "api.pitangus.dev", "path": "/v2"}))
        self.assertEqual(sorted(parsed["document"]["paths"]), ["/health", "/slots"])
        self.assertEqual(set(parsed["document"]["paths"]["/slots"]), {"get"})
        self.assertNotIn("webhooks", parsed["document"])
        json.dumps(parsed["document"])  # a YAML date became text
        self.assertEqual(len(parsed["sha256"]), 64)
        # The target is the definition's own host only when the scan includes it; never anything else.
        self.assertEqual(openapi_spec.target_url(parsed, HOST, [HOST, "api.pitangus.dev"]), "https://api.pitangus.dev/v2")
        self.assertEqual(openapi_spec.target_url(parsed, HOST, [HOST]), f"https://{HOST}/v2")
        given = json.loads(openapi_spec.for_zap(parsed, f"https://{HOST}/v2"))
        self.assertEqual(given["servers"], [{"url": f"https://{HOST}/v2"}])
        self.assertNotIn("evil.example", openapi_spec.for_zap(parsed, f"https://{HOST}/v2"))

    def test_swagger_two_and_relative_or_templated_servers(self):
        swagger = {"swagger": "2.0", "host": "localhost:8080", "basePath": "/api", "schemes": ["http"],
                   "paths": {"/a": {"get": {"responses": {"200": {"description": "ok"}}}}}}
        parsed = openapi_spec.parse(json.dumps(swagger).encode(), "s.json")
        self.assertEqual(openapi_spec.target_url(parsed, HOST, [HOST]), f"https://{HOST}/api")
        given = json.loads(openapi_spec.for_zap(parsed, f"https://{HOST}/api"))
        self.assertEqual((given["host"], given["basePath"], given["schemes"]), (HOST, "/api", ["https"]))
        for servers, expected in (([{"url": "/v1"}], f"https://{HOST}/v1"), ([{"url": "{scheme}://{host}/v3"}], f"https://{HOST}"),
                                  ([], f"https://{HOST}"), ([{"url": "https://evil.example/x y"}], f"https://{HOST}")):
            document = {"openapi": "3.0.0", "servers": servers, "paths": {"/a": {"get": {}}}}
            self.assertEqual(openapi_spec.target_url(openapi_spec.parse(json.dumps(document).encode()), HOST, [HOST]), expected, servers)

    def test_size_type_and_shape_limits(self):
        self.assertIn("5 MB", error(b"{" + b" " * openapi_spec.MAX_BYTES + b"}"))
        self.assertIn(".json, .yaml", error(b"{}", "spec.txt"))
        self.assertIn("empty", error(b""))
        self.assertIn("isn't an OpenAPI", error(b"[1, 2]"))
        self.assertIn("isn't an OpenAPI", error(b'{"openapi": "2.5", "paths": {}}'))
        self.assertIn("isn't an OpenAPI", error(b'{"openapi": "3.0.0"}'))
        self.assertIn("GET or HEAD", error(b'{"openapi": "3.0.0", "paths": {"/a": {"post": {}}}}'))
        self.assertIn("valid JSON or YAML", error(b'{"openapi": '))
        self.assertIn("valid JSON or YAML", error(b"\xff\xfe"))
        many = {"openapi": "3.0.0", "paths": {f"/p{index}": {"get": {}, "head": {}} for index in range(1001)}}
        self.assertIn("more than 2000", error(json.dumps(many).encode()))
        deep: dict = {}
        node = deep
        for _ in range(100):
            node["x"] = {}
            node = node["x"]
        self.assertIn("too deep", error(json.dumps({"openapi": "3.0.0", "paths": {"/a": {"get": {}}}, "x-deep": deep}).encode()))

    def test_yaml_aliases_and_tags_and_remote_references_are_refused(self):
        bomb = b"a: &a [x, x, x, x, x, x, x, x, x]\nb: &b [*a, *a, *a, *a, *a, *a, *a, *a]\nc: [*b, *b, *b, *b, *b, *b, *b, *b]\n"
        self.assertIn("aliases", error(bomb, "bomb.yaml"))
        self.assertIn("valid JSON or YAML", error(b"!!python/object/apply:os.system ['true']\n", "x.yaml"))
        for reference in ("https://evil.example/schemas.json#/A", "other.yaml#/A", "//evil.example/x", "file:///etc/passwd"):
            document = {"openapi": "3.0.0", "paths": {"/a": {"get": {"responses": {"200": {"$ref": reference}}}}}}
            self.assertIn("$ref", error(json.dumps(document).encode()), reference)
        for payload in (b"!!python/object/apply:os.system ['touch /tmp/pitangus-pwned']\n",
                        b"x: !!python/object/apply:subprocess.check_output [['id']]\n",
                        b"x: !!python/name:os.system\n",
                        b"x: !!python/object/new:subprocess.Popen [['id']]\n",
                        b"x: !!python/object:collections.OrderedDict {}\n",
                        b"x: !!python/module:os\n",
                        b"x: !!python/tuple [1, 2]\n",
                        b"openapi: 3.0.0\npaths: {/a: {get: !!python/object/apply:os.getcwd []}}\n"):
            self.assertIn("valid JSON or YAML", error(payload, "x.yaml"), payload)
        for payload in (b"openapi: &v 3.0.0\nswagger: *v\npaths: {}\n", b"a: &a {}\nb: {<<: *a}\n", b"- &x 1\n- *x\n"):
            self.assertIn("aliases", error(payload, "x.yaml"), payload)
        self.assertIn("valid JSON or YAML", error(b"openapi: 3.0.0\x07\npaths: {}\n", "x.yaml"))
        anchored = openapi_spec.parse(b"openapi: &v 3.0.0\npaths: {/a: {get: {responses: {'200': {description: ok}}}}}\n", "a.yaml")
        self.assertEqual(anchored["endpoints"], 1)
        local = {"openapi": "3.0.0", "paths": {"/a": {"get": {"responses": {"200": {"$ref": "#/components/responses/Ok"}}}}},
                 "components": {"responses": {"Ok": {"description": "ok"}}}}
        self.assertEqual(openapi_spec.parse(json.dumps(local).encode())["endpoints"], 1)

    def test_a_definition_url_must_be_https_on_a_pinned_host_of_the_scope(self):
        self.assertEqual(openapi_spec.check_url(f"https://{HOST}/openapi.json?v=1", [HOST]), (HOST, "/openapi.json?v=1"))
        for url in (f"http://{HOST}/o.json", f"https://{HOST}:8443/o.json", f"https://user@{HOST}/o.json", f"https://{HOST}/o.json#x",
                    "https://evil.example/o.json", f"https://a.{HOST}/o.json", "https://169.254.169.254/latest", f"https://{HOST}/a b", 5):
            with self.subTest(url=url), self.assertRaises(SpecError):
                openapi_spec.check_url(url, [HOST])


if __name__ == "__main__":
    unittest.main()
