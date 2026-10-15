"""Who brings in a vulnerable dependency, from the graph Trivy resolves out of any lockfile."""

import unittest

from pitangus.modules.scanning import dependency_graph


def package(name, version, relationship="indirect", depends=(), dev=False):
    return {"ID": f"{name}@{version}", "Name": name, "Version": version, "Relationship": relationship, "DependsOn": list(depends) or None,
            "Dev": dev or None}


# A Cargo project (Trivy marks the project itself as root) and a Poetry one (no root: direct and indirect only).
CARGO = {"Target": "/src/Cargo.lock", "Class": "lang-pkgs", "Type": "cargo", "Packages": [
    package("app", "0.1.0", "root", ["reqwest@0.12.9", "serde@1.0.200"]),
    package("reqwest", "0.12.9", "direct", ["hyper-rustls@0.27.3"]),
    package("hyper-rustls", "0.27.3", "indirect", ["rustls@0.23.20"]),
    package("rustls", "0.23.20", "indirect", ["rustls-webpki@0.103.10"]),
    package("rustls-webpki", "0.103.10"),
    package("serde", "1.0.200", "direct")]}
POETRY = {"Target": "/src/poetry.lock", "Class": "lang-pkgs", "Type": "poetry", "Packages": [
    package("fastapi", "0.110.1", "direct", ["starlette@0.37.2"]),
    package("starlette", "0.37.2", "indirect", ["anyio@4.3.0"]),
    package("anyio", "4.3.0"),
    package("pytest", "8.1.0", "direct", dev=True)]}
NO_GRAPH = {"Target": "/src/requirements.txt", "Class": "lang-pkgs", "Type": "pip", "Packages": [package("flask", "2.0.0", "direct")]}


def relative(path):
    return path.removeprefix("/src/")


class GraphTests(unittest.TestCase):
    def setUp(self):
        self.graphs = dependency_graph.graphs([CARGO, POETRY, NO_GRAPH, {"Target": "/src/main.tf", "Class": "config"}], relative)

    def test_only_lockfiles_with_a_graph_count(self):
        self.assertEqual(sorted(self.graphs), ["Cargo.lock", "poetry.lock"])

    def test_the_direct_dependency_at_the_top_of_the_chain_in_any_ecosystem(self):
        entries, direct = dependency_graph.introduced_by(self.graphs["Cargo.lock"], "rustls-webpki", "0.103.10")
        self.assertIs(direct, False)
        self.assertEqual(entries, [{"name": "rustls", "version": "0.23.20", "direct": "reqwest", "direct_version": "0.12.9",
                                    "chain": ["reqwest", "hyper-rustls", "rustls"]}])
        entries, direct = dependency_graph.introduced_by(self.graphs["poetry.lock"], "Starlette", "0.37.2")  # Python names: any case
        self.assertEqual((entries[0]["name"], entries[0]["direct"], direct), ("fastapi", "fastapi", False))
        self.assertEqual(dependency_graph.introduced_by(self.graphs["Cargo.lock"], "serde", "1.0.200"), ([], True))
        self.assertEqual(dependency_graph.introduced_by(self.graphs["Cargo.lock"], "tokio", "1.0.0"), ([], None))

    def test_annotate_whichever_engine_reported_it(self):
        def finding(path, name, version, **package):
            return {"scanner": "sca", "tool": "osv-scanner", "path": path, "package": {"name": name, "version": version, **package}}
        findings = [finding("Cargo.lock", "rustls-webpki", "0.103.10"), finding("poetry.lock", "pytest", "8.1.0", direct=None),
                    finding("requirements.txt", "flask", "2.0.0"), {"scanner": "sast", "path": "poetry.lock"}]
        dependency_graph.annotate(findings, self.graphs)
        self.assertEqual(findings[0]["package"]["introduced_by"][0]["direct"], "reqwest")
        self.assertIs(findings[0]["package"]["direct"], False)  # no engine said: the graph does
        self.assertIs(findings[1]["package"]["direct"], True)
        self.assertNotIn("introduced_by", findings[1]["package"])
        self.assertNotIn("introduced_by", findings[2]["package"])  # no graph for that lockfile: nothing added, nothing guessed


if __name__ == "__main__":
    unittest.main()
