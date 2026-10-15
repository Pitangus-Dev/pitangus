"""One name for each package and each advisory, whichever engine reports them, and the fingerprint built from both.

Trivy names an advisory by its CVE; OSV-Scanner by its GHSA or PYSEC, with the CVE as an alias. Each engine also writes
the ecosystem its own way (`pip`, `poetry`, `PyPI`…). Normalizing all of that recognizes the same advisory on the same
package and version, so every engine (and the image scan) gives a finding the same fingerprint.
"""

from __future__ import annotations

import hashlib
import re

# Each engine's package type → a common family.
FAMILY = {
    # JavaScript
    "npm": "npm", "yarn": "npm", "pnpm": "npm", "bun": "npm", "node-pkg": "npm",
    # Python
    "pypi": "pypi", "pip": "pypi", "pipenv": "pypi", "poetry": "pypi", "uv": "pypi", "pdm": "pypi",
    "python": "pypi", "python-pkg": "pypi", "conda-pkg": "pypi",
    # .NET
    "nuget": "nuget", "dotnet-core": "nuget", "dotnet": "nuget", "packages-props": "nuget",
    # Go, Rust, PHP, Ruby
    "go": "go", "gomod": "go", "gobinary": "go", "go-module": "go",
    "crates.io": "cargo", "cargo": "cargo", "rust-binary": "cargo", "rust-crate": "cargo",
    "packagist": "composer", "composer": "composer", "php-composer": "composer",
    "rubygems": "rubygems", "bundler": "rubygems", "gemspec": "rubygems", "gem": "rubygems",
    # JVM
    "maven": "maven", "pom": "maven", "gradle": "maven", "sbt": "maven", "jar": "maven", "java-archive": "maven",
    # Others
    "pub": "pub", "hex": "hex", "mix": "hex", "swifturl": "swift", "swift": "swift", "cocoapods": "cocoapods",
    "conancenter": "conan", "conan": "conan",
}
# Operating system packages (in container images), by distribution (Trivy) or package format (Grype): one family.
OS_FAMILIES = {"deb", "apk", "rpm", "debian", "ubuntu", "alpine", "redhat", "centos", "rocky", "alma", "amazon", "oracle", "photon", "suse",
               "opensuse", "opensuse.leap", "sles", "wolfi", "chainguard", "mariner", "azurelinux", "fedora", "bitnami"}


def family(ecosystem: str) -> str:
    value = (ecosystem or "").lower()
    return "os" if value in OS_FAMILIES else FAMILY.get(value, value or "unknown")


def package_name(ecosystem: str, name: str) -> str:
    """PyPI treats `-`, `_` and `.` alike (PEP 503); elsewhere, in practice, only case."""
    value = (name or "").strip().lower()
    return re.sub(r"[-_.]+", "-", value) if family(ecosystem) == "pypi" else value


def canonical_id(identifiers: set[str], fallback: str) -> str:
    """The CVE if there is one (the name shared across databases); otherwise the engine's own identifier."""
    cves = sorted(item for item in identifiers if item.startswith("CVE-"))
    return cves[0] if cves else fallback


def fingerprint(scanner: str, rule: str, ecosystem: str, name: str, version: str) -> str:
    """Stable across runs and independent of the path: the key that keeps tickets from repeating."""
    return hashlib.sha256(f"{scanner}|{rule}|{ecosystem}|{name}|{version}".encode()).hexdigest()


def dependency_fingerprint(identifiers: set[str], fallback: str, ecosystem: str, name: str, version: str) -> str:
    """The fingerprint of an advisory on a package version, the same whichever engine names it and however."""
    return fingerprint("sca", canonical_id(set(identifiers) | {fallback}, fallback), family(ecosystem),
                       package_name(ecosystem, name), str(version or ""))


def alias_fingerprints(identifiers: set[str], fallback: str, ecosystem: str, name: str, version: str) -> list[str]:
    """The fingerprints the same advisory had under its other names: a GHSA (or an OSV id) is the canonical one until
    the advisory gets a CVE, and then the CVE is. The registry moves a finding known by one of these to the current."""
    canonical = canonical_id(set(identifiers) | {fallback}, fallback)
    return [fingerprint("sca", item, family(ecosystem), package_name(ecosystem, name), str(version or ""))
            for item in sorted(set(identifiers) | {fallback}) if item and item != canonical and not item.startswith("CVE-")]


# Package family → purl type (https://github.com/package-url/purl-spec).
PURL_TYPE = {"npm": "npm", "pypi": "pypi", "go": "golang", "cargo": "cargo", "composer": "composer", "rubygems": "gem",
             "maven": "maven", "nuget": "nuget", "pub": "pub", "hex": "hex", "swift": "swift", "cocoapods": "cocoapods",
             "conan": "conan"}
# Ecosystems whose versions follow semantic versioning, where a leading `v` (Go always writes it) is no part of it.
SEMVER_FAMILIES = frozenset({"go", "npm", "cargo", "composer", "hex", "pub", "swift", "nuget"})
# Registries whose package names ignore case (Go modules, Maven and RubyGems don't).
CASELESS_FAMILIES = frozenset({"npm", "pypi", "nuget", "composer", "cargo"})


def normalized_version(ecosystem: str, version: str) -> str:
    """A version as its ecosystem compares it: Go's and semver's `v1.2.3` is `1.2.3`, PyPI ignores case and a
    leading `v` (PEP 440), and a Debian or RPM epoch of 0 is the same as none."""
    value, kind = str(version or "").strip(), family(ecosystem)
    if kind in SEMVER_FAMILIES or kind == "pypi":
        value = re.sub(r"^[vV](?=\d)", "", value)
    if kind == "pypi":
        value = value.lower()
    if kind == "os":
        value = re.sub(r"^0:", "", value)
    return value


def canonical_purl(ecosystem: str, name: str) -> str:
    """The package as a purl without its version, normalized per type by packageurl-python (PyPI's `Foo_Bar` is
    `foo-bar`); an ecosystem without a purl type keeps its family and lowercased name."""
    from packageurl import PackageURL
    kind, value = PURL_TYPE.get(family(ecosystem)), str(name or "").strip()
    if family(ecosystem) in CASELESS_FAMILIES:
        value = value.lower()
    if not kind or not value:
        return f"{family(ecosystem)}/{package_name(ecosystem, value)}"
    if kind == "maven" and ":" in value:
        namespace, _, last = value.partition(":")
    else:
        namespace, _, last = value.rpartition("/")
    try:
        return PackageURL(type=kind, namespace=namespace or None, name=last).to_string()
    except ValueError:
        return f"{kind}/{package_name(ecosystem, value)}"


def package_identity(identifiers: set[str], fallback: str, ecosystem: str, name: str, version: str) -> str:
    """An advisory on a package version, whichever engine reports it and however it writes the package, the ecosystem
    or the version (the canonical identity, findings/canonical.py)."""
    advisory = canonical_id(set(identifiers) | {fallback}, fallback)
    return hashlib.sha256(f"sca/2|{advisory}|{canonical_purl(ecosystem, name)}|{normalized_version(ecosystem, version)}".encode()).hexdigest()
