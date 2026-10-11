"""The URL inventory of a passive web scan: robots.txt, the sitemaps, ZAP's spider and the API definition, read safely
and kept to the scope. robots.txt and sitemap.xml are pitangus.dev's, as served on 2026-10-10."""

import unittest
from pathlib import Path

from pitangus.modules.scanning import web_seeds

OUTPUTS = Path(__file__).resolve().parent / "engine-outputs"
HOST, DOCS = "pitangus.dev", "docs.pitangus.dev"
PINS = {HOST: "172.67.153.40", DOCS: "104.21.32.173"}


def fixture(name: str) -> str:
    return (OUTPUTS / name).read_text(encoding="utf-8")


class Site:
    """`domains.https_get` over a dict of (host, path) → (status, body)."""

    def __init__(self, files: dict):
        self.files, self.asked = files, []

    def __call__(self, host, address, path, *, limit, seconds):
        self.asked.append((host, address, path))
        assert address == PINS[host]
        status, body = self.files.get((host, path), (404, b""))
        if isinstance(status, type) and issubclass(status, BaseException):
            raise status("unreachable")
        return status, body[:limit + 1]


class RobotsTests(unittest.TestCase):
    def test_allow_and_disallow_paths_and_sitemaps_in_scope(self):
        text = ("User-agent: *\nDisallow: /admin/  # the panel\nAllow: /public/*.pdf\nDisallow: /search?q=\nDisallow: /files$\n"
                "Disallow:\nDisallow: relative\nSitemap: https://pitangus.dev/sitemap-index.xml\nSitemap: https://evil.example/s.xml\n"
                "Sitemap: http://pitangus.dev/insecure.xml\n")
        paths, sitemaps = web_seeds.robots(text, HOST, [HOST])
        self.assertEqual(paths, [f"https://{HOST}/admin/", f"https://{HOST}/public/", f"https://{HOST}/search", f"https://{HOST}/files"])
        self.assertEqual(sitemaps, [f"https://{HOST}/sitemap-index.xml"])
        self.assertEqual(web_seeds.robots(fixture("robots-pitangus.dev.txt"), HOST, [HOST]),
                         ([f"https://{HOST}/"], [f"https://{HOST}/sitemap.xml"]))


class SitemapTests(unittest.TestCase):
    def test_pages_and_their_language_alternates(self):
        pages, children = web_seeds.sitemap(fixture("sitemap-pitangus.dev.xml").encode(), [HOST])
        self.assertEqual(sorted(set(pages)), [f"https://{HOST}/", f"https://{HOST}/es/"])
        self.assertEqual(children, [])

    def test_an_index_names_more_sitemaps_and_only_the_scope_counts(self):
        index = (b'<?xml version="1.0"?><sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
                 b"<sitemap><loc>https://pitangus.dev/a.xml</loc></sitemap><sitemap><loc>https://evil.example/b.xml</loc></sitemap>"
                 b"</sitemapindex>")
        self.assertEqual(web_seeds.sitemap(index, [HOST]), ([], [f"https://{HOST}/a.xml"]))
        urlset = (b'<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc> https://pitangus.dev/p?id=1 </loc></url>'
                  b"<url><loc>https://other.example/</loc></url><url><loc>javascript:alert(1)</loc></url></urlset>")
        self.assertEqual(web_seeds.sitemap(urlset, [HOST]), ([f"https://{HOST}/p"], []))

    def test_dangerous_or_broken_xml_is_refused_whole(self):
        laughs = (b'<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;">]>'
                  b"<urlset><url><loc>https://pitangus.dev/&lol2;</loc></url></urlset>")
        external = (b'<?xml version="1.0"?><!doctype x [<!entity e SYSTEM "file:///etc/passwd">]>'
                    b"<urlset><url><loc>https://pitangus.dev/&e;</loc></url></urlset>")
        for data in (laughs, external, b"<urlset><url><loc>", b"not xml", b"",
                     b"<urlset>" + b"<url><loc>https://pitangus.dev/x</loc></url>" * 60_000 + b"</urlset>"):
            self.assertEqual(web_seeds.sitemap(data, [HOST]), ([], []))


class KnownFilesTests(unittest.TestCase):
    def test_robots_then_the_sitemaps_it_names_and_sitemap_xml_on_each_host(self):
        index = (b"<sitemapindex><sitemap><loc>https://pitangus.dev/pages.xml</loc></sitemap>"
                 b"<sitemap><loc>https://docs.pitangus.dev/other.xml</loc></sitemap></sitemapindex>")
        site = Site({(HOST, "/robots.txt"): (200, b"Disallow: /private/\nSitemap: https://pitangus.dev/index.xml\n"
                                                   b"Sitemap: https://docs.pitangus.dev/x.xml\n"),
                     (HOST, "/index.xml"): (200, index),
                     (HOST, "/pages.xml"): (200, b"<urlset><url><loc>https://pitangus.dev/es/</loc></url></urlset>"),
                     (HOST, "/sitemap.xml"): (301, b""),
                     (DOCS, "/robots.txt"): (ConnectionRefusedError, b""),
                     (DOCS, "/sitemap.xml"): (200, b"<urlset><url><loc>https://docs.pitangus.dev/guide/</loc></url></urlset>")})
        found = web_seeds.known_files([HOST, DOCS], PINS, fetch=site)
        self.assertEqual(found, {"robots": [f"https://{HOST}/private/"], "sitemap": [f"https://{HOST}/es/", f"https://{DOCS}/guide/"]})
        # Each host's sitemaps are read on that host only; another host's are its own to read.
        self.assertEqual(site.asked, [(HOST, PINS[HOST], "/robots.txt"), (HOST, PINS[HOST], "/index.xml"), (HOST, PINS[HOST], "/sitemap.xml"),
                                      (HOST, PINS[HOST], "/pages.xml"), (DOCS, PINS[DOCS], "/robots.txt"), (DOCS, PINS[DOCS], "/sitemap.xml")])

    def test_a_sitemap_index_is_followed_only_so_far(self):
        children = b"".join(f"<sitemap><loc>https://pitangus.dev/s{index}.xml</loc></sitemap>".encode() for index in range(50))
        site = Site({(HOST, "/sitemap.xml"): (200, b"<sitemapindex>" + children + b"</sitemapindex>")})
        web_seeds.known_files([HOST], PINS, fetch=site)
        self.assertEqual(len(site.asked), 1 + web_seeds.SITEMAPS_MAX)

    def test_an_unpinned_host_is_never_asked(self):
        site = Site({})
        self.assertEqual(web_seeds.known_files(["unpinned.example"], PINS, fetch=site), {"robots": [], "sitemap": []})
        self.assertEqual(site.asked, [])


class OtherSourcesTests(unittest.TestCase):
    def test_zap_export_is_read_line_by_line_and_kept_to_the_scope(self):
        text = (f"https://{HOST}/\nhttps://{HOST}/es/?lang=es#top\nGET https://{HOST}/robots.txt\nhttps://evil.example/\n"
                f"http://{HOST}/plain\n\n\x00garbage\nhttps://{HOST}:8443/admin\n")
        self.assertEqual(web_seeds.zap_urls(text, [HOST]), [f"https://{HOST}/", f"https://{HOST}/es/", f"https://{HOST}/robots.txt"])

    def test_api_paths_without_parameters(self):
        api = {"document": {"paths": {"/users": {"get": {}}, "/users/{id}": {"get": {}}, "/login": {"head": {}}, "/health": {"get": {}}}}}
        self.assertEqual(web_seeds.api_urls(api, f"https://{HOST}/v1", [HOST]), [f"https://{HOST}/v1/users", f"https://{HOST}/v1/health"])
        self.assertEqual(web_seeds.api_urls(None, "", [HOST]), [])

    def test_merge_dedupes_sorts_shallow_first_caps_and_counts_each_source(self):
        inventory, counts = web_seeds.merge({"katana": [f"https://{HOST}/a/b", f"https://{HOST}/"], "sitemap": [f"https://{HOST}/", f"https://{HOST}/es/"],
                                             "zap": [f"https://{HOST}/robots.txt"]})
        self.assertEqual(inventory, [f"https://{HOST}/", f"https://{HOST}/robots.txt", f"https://{HOST}/a/b", f"https://{HOST}/es/"])
        self.assertEqual(counts, {"katana": 2, "sitemap": 1, "zap": 1})
        capped, _ = web_seeds.merge({"zap": [f"https://{HOST}/{index}" for index in range(900)]})
        self.assertEqual(len(capped), web_seeds.INVENTORY_MAX)


if __name__ == "__main__":
    unittest.main()
