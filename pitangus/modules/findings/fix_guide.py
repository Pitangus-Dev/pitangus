"""How to fix each finding, concretely: the package manager command, the code example, the steps.

- Dependencies: the manager comes from the file that declared it (package-lock.json → npm, poetry.lock → Poetry…)
  and the fix depends on whether the dependency is direct or transitive. For a transitive one, the graph Trivy resolves
  from the lockfile says who brings it in (`package.introduced_by`, scanning/dependency_graph.py), in any ecosystem;
  where the lockfile keeps ranges (scanning/declared_ranges.py), whether that package accepts the fixed version. When
  it doesn't, the direct dependency is updated first and the guide says why: updating the package alone would be a
  no-op. When it does, updating the package is enough. When the range is unknown, the guide updates the package and,
  if it stays below, the direct dependency. Every guide ends with a command that shows the installed version. The
  version is the one that closes every advisory for that package.
- Code: a before/after example for the rule (fix_examples), in its language.
- Secrets: rotate first; removing them from the code isn't enough, they're already in the history.
- An image's system packages: in the Dockerfile.
- Web: the scanner's own solution, a check of the response headers and the re-scan of the domain (web_fix).

Everything interpolated comes from the scanned repository (package names, paths): it is used as text and
whoever renders it escapes it. Odd names (spaces, quotes) get no command, only steps.
"""

from __future__ import annotations

import posixpath
import re

from pitangus.modules.intel.advisories import compare_versions
from pitangus.modules.intel.version_ranges import SYNTAX, allows
from pitangus.modules.findings import web_fix
from pitangus.modules.findings.fix_examples import EXAMPLES
from pitangus.shared.i18n import msg
from pitangus.shared.model import DependencyPath, Finding, Package

# What goes into a command: no shell metacharacters and no leading "-" (the manager would read it as an option).
SAFE_NAME = re.compile(r"[A-Za-z0-9@._][A-Za-z0-9@/._:+-]{0,199}")
SAFE_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+~:-]{0,99}")
# "Re-verify" scans the remote main branch (or the published image), not the local copy.
VERIFY = msg("findings.fix.verify")
VERIFY_DEPENDENCY = msg("findings.fix.verify_dependency")
VERIFY_IMAGE = msg("findings.fix.verify_image")
# Steps that send the reader to the panel's "Reverify" button: they mean nothing outside it (a prompt for an AI
# assistant, the terminal, a ticket).
PANEL_STEPS = frozenset({"findings.fix.verify", "findings.fix.verify_dependency", "findings.fix.verify_image",
                         "findings.fix.verify_web", "findings.fix.secret.verify"})


def panel_step(step) -> bool:
    return isinstance(step, dict) and step.get("$t") in PANEL_STEPS
# `action` is the language-neutral code for consumers that filter commands; `label` is what people read.
COMMAND_LABELS = {"update": msg("findings.fix.commands.update"), "reinstall": msg("findings.fix.commands.reinstall"),
                  "install": msg("findings.fix.commands.install")}
JS = ("npm", "yarn", "pnpm", "bun")
# Where the project declares its direct dependencies; and the managers whose update command for the direct dependency
# rewrites that declared range (`add …@latest`) instead of moving within it.
MANIFESTS = {"poetry": "pyproject.toml", "npm": "package.json", "yarn": "package.json", "bundler": "Gemfile"}
REWRITES = ("poetry", *JS)

# Dependency file → package manager.
MANAGERS = {"package-lock.json": "npm", "npm-shrinkwrap.json": "npm", "package.json": "npm", "yarn.lock": "yarn",
            "pnpm-lock.yaml": "pnpm", "bun.lock": "bun", "bun.lockb": "bun", "poetry.lock": "poetry", "uv.lock": "uv",
            "pipfile.lock": "pipenv", "pdm.lock": "pdm", "go.mod": "go", "go.sum": "go", "cargo.lock": "cargo", "cargo.toml": "cargo",
            "composer.lock": "composer", "composer.json": "composer", "gemfile.lock": "bundler", "pom.xml": "maven",
            "gradle.lockfile": "gradle", "packages.lock.json": "dotnet", "packages.config": "dotnet", "pubspec.lock": "pub", "mix.lock": "mix"}
OS_DATABASES = {"var/lib/dpkg/status": "apt", "lib/apk/db/installed": "apk", "var/lib/rpm": "dnf", "usr/lib/sysimage/rpm": "dnf"}


def manager(path: str, ecosystem: str) -> str | None:
    name = posixpath.basename(path or "").lower()
    if name in MANAGERS:
        return MANAGERS[name]
    if name.endswith(".txt") and "requirements" in name[:-4]:
        return "pip"
    if name.endswith((".gradle", ".gradle.kts")):
        return "gradle"
    if name.endswith((".csproj", ".fsproj", ".vbproj")):
        return "dotnet"
    for database, tool in OS_DATABASES.items():
        if (path or "").lstrip("/").startswith(database):
            return tool
    return {"debian": "apt", "ubuntu": "apt", "alpine": "apk", "redhat": "dnf", "rocky": "dnf", "alma": "dnf",
            "amazon": "dnf", "oracle": "dnf", "centos": "dnf", "fedora": "dnf"}.get((ecosystem or "").lower())


def _check(tool: str | None, name: str, target: str) -> dict | None:
    """The command that shows which version ended up installed, so "updated" is checked, not assumed."""
    if tool == "go" and name in ("stdlib", "toolchain"):
        return None
    group, _, artifact = name.partition(":")
    code = {"npm": f"npm ls {name}", "yarn": f"yarn why {name}", "pnpm": f"pnpm why {name}", "poetry": f"poetry show {name}",
            "uv": f"uv tree --invert --package {name}", "pip": f"pip show {name}", "go": f"go list -m {name}", "cargo": f"cargo tree --invert {name}", "composer": f"composer show {name}", "bundler": f"bundle info {name}",
            "maven": f"mvn dependency:tree -Dincludes={group}:{artifact}" if artifact else None,
            "gradle": f"./gradlew dependencyInsight --dependency {artifact}" if artifact else None}.get(tool or "")
    return {"label": msg("findings.fix.commands.check_version", version=target), "action": "check", "code": code} if code else None


def _update_direct(tool: str | None, name: str, dev: bool) -> str | None:
    """Updates the direct dependency that brings a transitive one in, for when its range is what holds the transitive
    one back. Go, Maven and Gradle don't need it: they set a transitive version on their own."""
    if not SAFE_NAME.fullmatch(name):
        return None
    flag = " -D" if dev else ""
    return {"npm": f"npm install{flag} {name}@latest", "yarn": f"yarn add{flag} {name}@latest", "pnpm": f"pnpm add{flag} {name}@latest",
            "bun": f"bun add{' -d' if dev else ''} {name}@latest",
            "poetry": f"poetry add{' --group dev' if dev else ''} {name}@latest", "uv": f"uv lock --upgrade-package {name}",
            "pipenv": f"pipenv update {name}", "pdm": f"pdm update {name}", "cargo": f"cargo update -p {name}",
            "composer": f"composer update {name} --with-dependencies", "bundler": f"bundle update {name}",
            "dotnet": f"dotnet add package {name}", "pub": f"dart pub upgrade {name}", "mix": f"mix deps.update {name}"}.get(tool or "")


def _introduced(package: Package, tool: str | None, target: str) -> tuple[DependencyPath | None, bool | None]:
    """Who brings a transitive dependency in (from the lockfile's graph) and whether every package that requires it
    accepts `target`: False names the one that doesn't, True only when all of them are known to, None when a range is
    unknown. (None, None) when the graph doesn't say."""
    entries = [entry for entry in package.get("introduced_by") or [] if isinstance(entry, dict) and entry.get("name") and entry.get("direct")]
    if not entries:
        return None, None
    verdicts = [allows(SYNTAX.get(tool or ""), entry.get("requires"), target) for entry in entries]
    blocking = next((entry for entry, verdict in zip(entries, verdicts) if verdict is False), None)
    if blocking:
        return blocking, False
    return entries[0], True if all(verdicts) and not package.get("introduced_by_more") else None


def _dependency(finding: Finding, target: str | None) -> dict:
    package = finding.get("package") or {}
    name, version, path = str(package.get("name") or ""), str(package.get("version") or ""), str(finding.get("path") or "")
    tool = manager(path, str(package.get("ecosystem") or ""))
    direct = package.get("direct")
    steps, commands, example = [], [], None
    if not target:
        steps = [msg("findings.fix.no_fix.none_published", package=name), msg("findings.fix.no_fix.check_usage"),
                 msg("findings.fix.no_fix.mitigate"), msg("findings.fix.no_fix.accept")]
        return {"kind": "dependency", "steps": steps, "commands": [], "example": None}
    if not SAFE_NAME.fullmatch(name) or not SAFE_VERSION.fullmatch(target):
        return {"kind": "dependency", "steps": [msg("findings.fix.manual_update", package=name, version=target, path=path), VERIFY_DEPENDENCY],
                "commands": [], "example": None}
    add = lambda action, code: commands.append({"label": COMMAND_LABELS[action], "action": action, "code": code})
    transitive = direct is False
    dev = bool(package.get("dev"))  # a dev dependency: the command must not move it to production
    fixed = package.get("fixed_version")
    lead, fits = _introduced(package, tool, target) if transitive else (None, None)
    names: dict = {}
    if lead:
        names = {"package": name, "version": version, "target": target, "parent": lead["name"], "parent_version": lead.get("version") or "?",
                 "requires": lead.get("requires") or "", "direct": lead["direct"], "direct_version": lead.get("direct_version") or "?"}
    override = {"npm": "overrides", "yarn": "resolutions", "pnpm": "pnpm.overrides", "bun": "overrides"}.get(tool or "", "")
    if fixed and fixed != target:
        steps.append(msg("findings.fix.closes_all", version=target, package=name, fixed=fixed))
    if tool in JS:
        if transitive and fits and tool == "npm":
            add("update", f"npm update {name}")  # within the range of what requires it: npm moves it in place
        elif transitive and fits is not False:
            steps.append(msg("findings.fix.npm_transitive", package=name, field=override))
            # Within the range of what requires it, the override only moves it; otherwise updating that one is cleaner.
            note = "" if fits else msg("findings.fix.path.override_note", direct=lead["direct"]) if lead else msg("findings.fix.override_note")
            example = {"language": "json", "file": "package.json", "before": "", "after": ("{\n  \"pnpm\": {\n    \"overrides\": {\n      \"" + name + "\": \">=" + target + "\"\n    }\n  }\n}"
                                                                   if tool == "pnpm" else
                                                                   "{\n  \"" + override + "\": {\n    \"" + name + "\": \">=" + target + "\"\n  }\n}"), "note": note}
            add("reinstall", {"npm": "npm install", "yarn": "yarn install", "pnpm": "pnpm install", "bun": "bun install"}[tool])
        elif not transitive:
            flag = " -D" if dev else ""
            add("update", {"npm": f"npm install{flag} {name}@{target}", "yarn": f"yarn add{flag} {name}@{target}",
                              "pnpm": f"pnpm add{flag} {name}@{target}", "bun": f"bun add{' -d' if dev else ''} {name}@{target}"}[tool])
    elif tool == "pip":
        steps.append(msg("findings.fix.pip_line", path=path, package=name, version=target))
        add("install", f"pip install -r {path}" if SAFE_NAME.fullmatch(path) else f'pip install "{name}>={target}"')
    elif tool == "poetry":
        add("update", f"poetry update {name}" if transitive else f'poetry add{" --group dev" if dev else ""} "{name}>={target}"')
    elif tool == "uv":
        add("update", f"uv lock --upgrade-package {name}" if transitive else f'uv add{" --dev" if dev else ""} "{name}>={target}"')
    elif tool == "pipenv":
        add("update", f'pipenv install "{name}>={target}"')
    elif tool == "pdm":
        add("update", f"pdm update {name}" if transitive else f'pdm add{" -d" if dev else ""} "{name}>={target}"')
    elif tool == "go" and name in ("stdlib", "toolchain"):
        # Go's standard library isn't updated with go get: rebuild with a fixed Go version.
        steps.append(msg("findings.fix.go_stdlib", version=target.lstrip("v")))
        add("update", f"go mod edit -toolchain=go{target.lstrip('v')}")
    elif tool == "go":
        add("update", f"go get {name}@{target if target.startswith('v') else 'v' + target} && go mod tidy")
    elif tool == "cargo":
        add("update", f"cargo update -p {name}@{version} --precise {target}" if SAFE_VERSION.fullmatch(version) else f"cargo update -p {name} --precise {target}")
    elif tool == "composer":
        add("update", f"composer update {name} --with-dependencies" if transitive else f'composer require{" --dev" if dev else ""} "{name}:^{target}"')
    elif tool == "bundler":
        steps.append(msg("findings.fix.bundler_pin", package=name, version=target))
        add("update", f"bundle update {name}")
    elif tool in ("maven", "gradle") and ":" in name:
        group, artifact = name.split(":", 1)
        if tool == "maven" and direct:
            steps.append(msg("findings.fix.maven_direct", artifact=artifact))
            example = {"language": "xml", "file": "pom.xml", "before": "", "note": "", "after":
                       f"<dependency>\n  <groupId>{group}</groupId>\n  <artifactId>{artifact}</artifactId>\n  <version>{target}</version>\n</dependency>"}
        elif tool == "maven":
            steps.append(msg("findings.fix.maven_managed"))
            example = {"language": "xml", "file": "pom.xml", "before": "", "note": "", "after":
                       f"<dependencyManagement>\n  <dependencies>\n    <dependency>\n      <groupId>{group}</groupId>\n"
                       f"      <artifactId>{artifact}</artifactId>\n      <version>{target}</version>\n    </dependency>\n  </dependencies>\n</dependencyManagement>"}
        else:
            steps.append(msg("findings.fix.gradle_constraint"))
            example = {"language": "kotlin", "file": "build.gradle", "before": "", "note": "",
                       "after": f"dependencies {{\n    constraints {{\n        implementation(\"{group}:{artifact}:{target}\")\n    }}\n}}"}
    elif tool == "dotnet":
        add("update", f"dotnet add package {name} --version {target}")
    elif tool == "pub":
        add("update", f"dart pub upgrade {name}")
    elif tool == "mix":
        add("update", f"mix deps.update {name}")
    elif tool in ("apt", "apk", "dnf"):
        steps.append(msg("findings.fix.os_rebuild"))
        steps.append(msg("findings.fix.os_dockerfile"))
        example = {"language": "dockerfile", "file": "Dockerfile", "before": "", "note": "", "after": {
            "apt": f"RUN apt-get update && apt-get install -y --only-upgrade {name} && rm -rf /var/lib/apt/lists/*",
            "apk": f"RUN apk upgrade --no-cache {name}", "dnf": f"RUN dnf upgrade -y {name} && dnf clean all"}[tool]}
    else:
        steps.append(msg("findings.fix.generic_update", package=name, installed=version, version=target, path=path))
    check = _check(tool, name, target)
    if check:
        commands.append(check)
    extra: dict = {}
    via = lead is not None and lead["direct"] != lead["name"]
    if lead and fits is False:
        # What requires it doesn't accept the fixed version: updating the package alone is a no-op, so the direct
        # dependency moves first and the package's own command, if any, comes after it.
        upgrade = _update_direct(tool, lead["direct"], bool(lead.get("direct_dev")))
        applying = [command for command in commands if command["action"] != "check"]
        if tool == "npm":  # once the direct one accepts it, npm moves it in place
            applying = [{"action": "update", "code": f"npm update {name}"}]
        checks = [command for command in commands if command["action"] == "check"]
        if applying and upgrade:
            applying[0] = {**applying[0], "label": msg("findings.fix.commands.update_then", package=name)}
        first = [{"label": msg("findings.fix.commands.update_first", package=lead["direct"]), "action": "update", "code": upgrade}] if upgrade else []
        commands = first + (applying if upgrade else []) + checks
        extra = {"action": msg("findings.fix.path.action_blocked" if applying else "findings.fix.path.action_blocked_alone", **names)}
        steps.insert(0, msg("findings.fix.path.blocked_via" if via else "findings.fix.path.blocked", **names))
        if lead.get("direct_requires") and tool in MANIFESTS:
            steps.insert(1, msg("findings.fix.path.declared_rewritten" if tool in REWRITES else "findings.fix.path.declared",
                                manifest=MANIFESTS[tool], range=lead["direct_requires"], **names))
        if tool in JS:  # forcing it goes against what requires it: only once no release of the direct one helps
            steps.append(msg("findings.fix.path.force", field=override, **names))
        else:
            steps.append(msg("findings.fix.path.no_release_yet", **names))
    elif lead and fits:
        steps.insert(0, msg("findings.fix.path.fits", **names))
    elif lead:
        # The range is unknown: update the package, check it, and if it didn't move, the direct dependency.
        steps.insert(0, msg("findings.fix.path.from_via" if via else "findings.fix.path.from", **names))
        upgrade = None if tool in JS else _update_direct(tool, lead["direct"], bool(lead.get("direct_dev")))
        if upgrade:
            extra = {"action": msg("findings.fix.path.action", **names)}
            commands.append({"label": msg("findings.fix.commands.if_stuck", package=lead["direct"], version=target), "action": "update", "code": upgrade})
        elif tool not in JS + ("go", "maven", "gradle"):
            steps.insert(1, msg("findings.fix.path.if_stuck", **names))
    elif transitive and tool not in JS + ("maven", "gradle"):
        steps.insert(0, msg("findings.fix.transitive_other", package=name, version=target))
    also = [str(item) for item in package.get("also_in") or [] if item][:5]
    if also:  # a monorepo: the same version in other lockfiles, each updated on its own
        steps.append(msg("findings.fix.also_in", package=name, version=version, paths=", ".join(also)))
    steps.append(VERIFY_IMAGE if tool in ("apt", "apk", "dnf") else VERIFY_DEPENDENCY)
    return {"kind": "dependency", "steps": steps, "commands": commands, "example": example, **extra}


def _secret(finding: Finding) -> dict:
    return {"kind": "secret", "commands": [], "example": None, "steps": [
        msg("findings.fix.secret.revoke"), msg("findings.fix.secret.review_use"), msg("findings.fix.secret.vault"),
        msg("findings.fix.secret.remove", path=str(finding.get("path") or "")), msg("findings.fix.secret.history"),
        msg("findings.fix.secret.verify")]}


def guide(finding: Finding, *, target: str | None = None) -> dict | None:
    scanner = finding.get("scanner")
    if finding.get("malicious"):
        # Nothing to update: remove it; whatever installed it is compromised (see advisories.malicious_finding).
        return {"kind": "dependency", "steps": [finding.get("remediation") or "", VERIFY], "commands": [], "example": None}
    if scanner == "sca" and (finding.get("package") or {}).get("name"):
        return _dependency(finding, target or (finding.get("package") or {}).get("fixed_version"))
    if scanner == "secrets":
        return _secret(finding)
    if scanner == "dast":
        return web_fix.guide(finding)
    if scanner == "sast" and finding.get("rule_id") in EXAMPLES:
        language, before, after, note = EXAMPLES[finding["rule_id"]]
        return {"kind": "code", "steps": [finding.get("remediation") or "", VERIFY], "commands": [],
                "example": {"language": language, "before": before, "after": after, "note": note}}
    if finding.get("remediation"):
        return {"kind": "config" if scanner in ("iac", "cicd") else "code", "steps": [finding["remediation"], VERIFY],
                "commands": [], "example": None}
    return None


def attach(findings: list[Finding], *, among: list[Finding] | None = None) -> list[Finding]:
    """Adds `fix` to each finding. For dependencies, the version that closes every advisory for the same package
    (among `among`, every finding of the asset, when `findings` is only part of it)."""
    every = findings if among is None else among
    targets: dict[tuple, str] = {}
    # A malicious package is not upgraded: its other advisories must not suggest "upgrade to…" either.
    hostile = {(item.get("path"), (item.get("package") or {}).get("name"), (item.get("package") or {}).get("version"))
               for item in every if item.get("malicious")}
    for finding in every:
        package = finding.get("package") or {}
        fixed = package.get("fixed_version")
        if finding.get("scanner") == "sca" and fixed and (finding.get("path"), package.get("name"), package.get("version")) not in hostile:
            key = (finding.get("path"), package.get("name"), package.get("version"))
            current = targets.get(key)
            targets[key] = fixed if current is None or compare_versions(fixed, current) > 0 else current
    for finding in findings:
        if finding.get("scanner") == "dast":
            web_fix.prioritize(finding)
        package = finding.get("package") or {}
        key = (finding.get("path"), package.get("name"), package.get("version"))
        if key in hostile and not finding.get("malicious"):
            finding["fix"] = {"kind": "dependency", "commands": [], "example": None,
                              "steps": [msg("findings.fix.malicious_sibling", package=str(package.get("name") or ""),
                                            version=str(package.get("version") or "")), VERIFY]}
            continue
        fix = guide(finding, target=targets.get(key))
        if fix:
            finding["fix"] = fix
    return findings
