"""Authorised code sources: the fixed workspace and repositories listed through the API."""

from __future__ import annotations

import io
import json
import os
import re
import shutil
import tarfile
import time
from pathlib import Path, PurePosixPath
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import Request
from pitangus.shared import coverage_units, encodings, http, settings
from pitangus.shared.i18n import msg, text
from pitangus.version import USER_AGENT


# These caps are not product policy: they defend against malicious decompression
# and runaway runs. What bounds the real work is the list of what the analysers
# can read, not a byte budget.
MAX_ARCHIVE = 1_000_000_000      # compressed download, streamed to disk
MAX_EXPANSION = 5_000_000_000    # bytes read from the archive before suspecting a bomb
MAX_FILES = 200_000              # brake on runaway runs
MAX_FILE = 2_000_000             # per file: anything bigger is generated code or data
MAX_MANIFEST = 64_000_000        # manifests and lockfiles: recognised by name; a large lockfile is normal
MAX_TOTAL = 2_000_000_000        # accumulated source; should never be reached
SECRET_ONLY_MAX_TOTAL = 1_000_000_000  # what only the secret pass reads (binaries, hidden files): its own budget
UNEXAMINED_MAX = 5_000           # committed files left out that a run lists by path; beyond it, by folder (coverage_units.compact)
TREE_REQUESTS = 400             # requests to list a commit's tree the provider truncated; a folder past them is declared whole
LFS_POINTER_MAX = 1024          # a Git LFS pointer is smaller than this, by its specification
# Code providers reached with a personal token. GitLab is written but untested against gitlab.com, so it stays off
# (not listed, not scannable) until it is; adding it here turns it back on.
TOKEN_SETTINGS = {"github": "GITHUB_TOKEN", "gitlab": "GITLAB_TOKEN"}
ENABLED_PROVIDERS = ("github",)
# What enters a snapshot is decided by what was committed, never by a folder's name alone (docs/scanning-code.md, "What
# each engine reads"):
# * Version control metadata is never content.
NOT_CONTENT = {".git", ".hg", ".svn"}
# * A folder copied from disk (not from git) also leaves out what tools install or cache on that machine, which nobody
#   commits: counted and named in the snapshot step. From an archive or a commit, whatever is there was committed.
LOCAL_ONLY = {"node_modules", "bower_components", "jspm_packages", "venv", "site-packages", "__pycache__"}
# * Everything else committed is read by the secret scanners, whatever its name. The other engines don't read installed
#   dependencies (anywhere) nor build output (at the root, next to a build manifest, or holding source maps): those
#   folders go to the copy only the secret scanners read (`secrets_root`), and every engine lists them unexamined with
#   that reason. Files no other engine reads by their name (hidden folders, binaries, images, source maps) go to that
#   copy too. Only a file over the size limit or the budget stays out, listed by path (`_left_out`).
DEPENDENCY_FOLDERS = {"node_modules", "bower_components", "jspm_packages", "site-packages", "venv", "vendor"}
OUTPUT_FOLDERS = {"dist", "build", "out", "target", "coverage", "htmlcov", "storybook-static", "__pycache__"}
# No code analyser looks at any of this, so it must not spend budget or crowd
# out a source file that does matter.
# An allowlist, not a denylist: a 600 MB repository usually holds a few MB of
# code and the rest is assets nobody is going to analyse.
SOURCE_SUFFIXES = {
    ".py", ".pyi", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".vue", ".svelte",
    ".java", ".kt", ".kts", ".go", ".rb", ".php", ".cs", ".rs", ".swift", ".scala", ".dart",
    ".c", ".h", ".cpp", ".cc", ".cxx", ".hpp", ".m", ".mm", ".lua", ".pl", ".pm",
    ".ex", ".exs", ".erl", ".clj", ".groovy", ".sh", ".bash", ".zsh", ".ps1",
    ".sql", ".graphql", ".proto", ".tf", ".tfvars", ".rules",
    ".erb", ".jinja", ".jinja2", ".j2", ".twig", ".blade", ".hbs", ".ejs", ".pug",
    ".yml", ".yaml", ".json", ".toml", ".ini", ".cfg", ".conf", ".properties", ".env",
}
# Manifests and extensionless files needed for SCA, secrets and IaC.
SOURCE_NAMES = {
    "dockerfile", "containerfile", "makefile", "rakefile", "gemfile", "procfile",
    "requirements.txt", "pipfile", "poetry.lock", "pyproject.toml", "setup.py", "setup.cfg",
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json",
    "go.mod", "go.sum", "pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle",
    "gemfile.lock", "composer.json", "composer.lock", "cargo.toml", "cargo.lock",
}
# Dependency manifests and lockfiles for each ecosystem. Recognised by name or extension,
# never by size: without them dependency analysis sees nothing.
MANIFEST_NAMES = {
    # JavaScript / TypeScript
    "package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock",
    "deno.json", "deno.lock",
    # Python
    "requirements.txt", "pipfile", "pipfile.lock", "poetry.lock", "pyproject.toml", "setup.py", "setup.cfg",
    "uv.lock", "pdm.lock", "pylock.toml",
    # .NET
    "packages.config", "packages.lock.json", "directory.packages.props", "directory.build.props",
    "paket.dependencies", "paket.lock",
    # Java, Kotlin, Scala
    "pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts", "gradle.lockfile",
    "libs.versions.toml", "verification-metadata.xml",
    # Go, Rust, PHP, Ruby
    "go.mod", "go.sum", "go.work", "go.work.sum", "cargo.toml", "cargo.lock", "composer.json", "composer.lock",
    "gemfile", "gemfile.lock", "gems.rb", "gems.locked",
    # Dart, Elixir, Erlang, Swift, Objective-C, C/C++, R, Haskell
    "pubspec.yaml", "pubspec.lock", "mix.exs", "mix.lock", "rebar.config", "rebar.lock", "package.swift",
    "package.resolved", "podfile", "podfile.lock", "cartfile", "cartfile.resolved", "conanfile.txt", "conanfile.py",
    "conan.lock", "vcpkg.json", "renv.lock", "stack.yaml.lock", "cabal.project.freeze",
}
MANIFEST_SUFFIXES = {".csproj", ".fsproj", ".vbproj", ".nuspec", ".sbt", ".gradle", ".lock", ".lockfile"}


def is_manifest(relative: Path) -> bool:
    name = relative.name.lower()
    return name in MANIFEST_NAMES or relative.suffix.lower() in MANIFEST_SUFFIXES or name.startswith("requirements")


# Build output and bundles: text, but generated, and it drowns the signal.
# Secrets show up in any text, not just code: docs, sample configuration and notes are
# among the most common places. SAST ignores these files but Betterleaks reads them, and
# leaving them out caused false negatives.
TEXT_SUFFIXES = {
    ".md", ".markdown", ".mdx", ".txt", ".rst", ".adoc", ".html", ".htm", ".xml", ".csv", ".tsv", ".ipynb",
    ".log", ".pem", ".key", ".crt", ".cer", ".pub", ".asc", ".tpl", ".template", ".example", ".sample", ".dist",
    ".plist", ".xcconfig", ".http", ".rest", ".postman_collection", ".har", ".cnf", ".config",
}
SECRET_NAMES = {".npmrc", ".pypirc", ".netrc", ".dockercfg", ".git-credentials", ".htpasswd", "id_rsa", "id_dsa",
                "id_ecdsa", "id_ed25519", "credentials", "authorized_keys", "known_hosts", ".s3cfg", ".boto"}
# Dot-prefixed entries are dropped except CI/CD pipelines (Checkov, zizmor). Credential files (.env, .npmrc, id_rsa…)
# never enter the snapshot the engines share: they go to a sibling folder only the secret scanners read, removed as soon
# as they're done (`secrets_root`).
DOT_FOLDERS = {".github", ".gitlab", ".circleci", ".buildkite", ".tekton", ".devcontainer"}
DOT_FILES = {".gitlab-ci.yml", ".gitlab-ci.yaml", ".pre-commit-config.yaml", ".pre-commit-hooks.yaml"}


class SourceError(ValueError):
    """`message` is what people read (rendered per reader); str() stays English, for logs."""

    def __init__(self, message):
        super().__init__(text(message, "en"))
        self.message = message


def _joined(problems: list) -> dict | str:
    """Several problems in one line; each keeps its own message."""
    if not problems:
        return ""
    result = problems[0]
    for item in problems[1:]:
        result = msg("sources.errors.joined", first=result, second=item)
    return result


def _request(url: str, token: str, provider: str, *, redirect_host: str | None = None, accept: str = "application/json") -> bytes:
    headers = {"Accept": accept, "User-Agent": USER_AGENT}
    if provider == "github":
        headers["Authorization"] = f"Bearer {token}"
        headers["X-GitHub-Api-Version"] = "2022-11-28"
    else:
        headers["PRIVATE-TOKEN"] = token
    opener = http.opener()
    try:
        try:
            response = opener.open(Request(url, headers=headers), timeout=12)
        except HTTPError as exc:
            if exc.code != 302 or not redirect_host:
                raise
            target = exc.headers.get("Location", "")
            parsed = urlsplit(target)
            if parsed.scheme != "https" or parsed.hostname != redirect_host or parsed.username or parsed.password:
                raise SourceError(msg("sources.errors.redirect_not_allowed")) from None
            # The temporary URL is fetched without the original credential.
            response = opener.open(Request(target, headers={"User-Agent": USER_AGENT}), timeout=20)
        with response:
            body = response.read(MAX_ARCHIVE + 1)
            if len(body) > MAX_ARCHIVE:
                raise SourceError(msg("sources.errors.over_download_limit"))
            return body
    except (HTTPError, URLError, TimeoutError, OSError) as exc:
        raise SourceError(msg("sources.errors.provider_unreachable")) from exc


def _download_timeout() -> int:
    try:
        return settings.integer("PITANGUS_DOWNLOAD_TIMEOUT")
    except ValueError:
        return 900


def _download_archive(url: str, token: str, provider: str, destination: Path,
                      *, redirect_host: str | None = None, progress=None) -> int:
    """Downloads the tarball to disk in chunks. A repository of hundreds of MB does not fit in memory.

    The socket `timeout` only fires when nothing arrives; a trickling connection could take
    hours without a word. Hence an overall deadline, and progress reports on what was downloaded."""
    deadline = time.monotonic() + _download_timeout()
    headers = {"Accept": "application/vnd.github+json", "User-Agent": USER_AGENT}
    if provider == "github":
        headers["Authorization"] = f"Bearer {token}"
        headers["X-GitHub-Api-Version"] = "2022-11-28"
    else:
        headers["PRIVATE-TOKEN"] = token
    opener = http.opener()
    try:
        try:
            response = opener.open(Request(url, headers=headers), timeout=30)
        except HTTPError as exc:
            if exc.code != 302 or not redirect_host:
                raise
            target = exc.headers.get("Location", "")
            parsed = urlsplit(target)
            if parsed.scheme != "https" or parsed.hostname != redirect_host or parsed.username or parsed.password:
                raise SourceError(msg("sources.errors.redirect_not_allowed")) from None
            # The temporary URL is fetched without the original credential.
            response = opener.open(Request(target, headers={"User-Agent": USER_AGENT}), timeout=180)
        written, reported = 0, time.monotonic()
        with response, open(destination, "wb") as handle:
            while True:
                chunk = response.read1(1_048_576)
                if not chunk:
                    break
                written += len(chunk)
                if written > MAX_ARCHIVE:
                    raise SourceError(msg("sources.errors.archive_too_big"))
                handle.write(chunk)
                now = time.monotonic()
                if now > deadline:
                    raise SourceError(msg("sources.errors.download_timeout", minutes=_download_timeout() // 60,
                                          mb=written // 1_048_576, provider=provider.capitalize()))
                if progress and now - reported >= 10:
                    progress("info", msg("sources.progress.downloading", mb=f"{written / 1_048_576:.0f}"))
                    reported = now
        if progress:
            progress("info", msg("sources.progress.downloaded", mb=f"{written / 1_048_576:.1f}"))
        return written
    except (HTTPError, URLError, TimeoutError, OSError) as exc:
        raise SourceError(msg("sources.errors.download_failed")) from exc


def unavailable(provider: str):
    """Why a known provider can't be used yet, or None when it can."""
    if provider in TOKEN_SETTINGS and provider not in ENABLED_PROVIDERS:
        return msg("sources.errors.provider_in_development", provider={"gitlab": "GitLab"}.get(provider, provider))
    return None


def list_repositories(provider: str, token: str | None = None) -> list[dict]:
    if reason := unavailable(provider):
        raise SourceError(reason)
    if provider not in ENABLED_PROVIDERS:
        raise SourceError(msg("sources.errors.invalid_provider"))
    token = token or settings.text(TOKEN_SETTINGS[provider])
    if not token:
        return []
    url = ("https://api.github.com/user/repos?per_page=50&sort=updated"
           if provider == "github" else
           "https://gitlab.com/api/v4/projects?membership=true&per_page=50&order_by=last_activity_at")
    try:
        rows = json.loads(_request(url, token, provider))
    except (ValueError, UnicodeDecodeError) as exc:
        raise SourceError(msg("sources.errors.invalid_data")) from exc
    if not isinstance(rows, list):
        raise SourceError(msg("sources.errors.invalid_list"))
    result = []
    for item in rows[:50]:
        if not isinstance(item, dict):
            continue
        name = item.get("full_name") if provider == "github" else item.get("path_with_namespace")
        identifier = name if provider == "github" else item.get("id")
        if not isinstance(name, str) or not name or not identifier:
            continue
        result.append({"id": f"{provider}:{identifier}", "name": name,
                       "provider": provider, "private": item.get("private", False) if provider == "github" else item.get("visibility") != "public",
                       "branch": item.get("default_branch")})
    return result


def available_sources(tokens: dict[str, str] | None = None, installation_id: int | list[int] | None = None) -> dict:
    """Every analysable repository (CLI). The panel uses `source_page`, which does not list whole organisations."""
    tokens = tokens or {}
    sources = []
    statuses = {}
    installations = [installation_id] if isinstance(installation_id, int) else installation_id or []
    if installations:
        # Each installation authorises only the repositories chosen in that account.
        from pitangus.modules.integrations.github import GitHubAppError, installation_repositories
        errors = []
        seen = set()
        for current in installations:
            try:
                for entry in installation_repositories(current):
                    key = entry.get("uid") or entry["id"]
                    if key not in seen:
                        sources.append({**entry, "installation_id": current, "account": entry["name"].split("/", 1)[0]})
                        seen.add(key)
            except GitHubAppError as exc:
                errors.append(msg("sources.errors.installation", id=current, detail=exc.message))
        statuses["github"] = {"configured": True, "origin": "github_app"}
        if errors:
            statuses["github"]["error"] = _joined(errors)
    for provider in ENABLED_PROVIDERS:
        env = TOKEN_SETTINGS[provider]
        if provider in statuses:
            continue
        origin = "session" if tokens.get(provider) else "environment" if settings.is_set(env) else None
        statuses[provider] = {"configured": bool(origin), "origin": origin}
        if statuses[provider]["configured"]:
            try:
                sources.extend(list_repositories(provider, tokens.get(provider)))
            except SourceError:
                statuses[provider]["error"] = msg("sources.errors.list_failed")
    return {"sources": sources, "providers": statuses}


def _paged(first: list[dict], fetch, per_page: int, decorate):
    """Rows [offset, offset+limit) of a source paginated by GitHub: two pages at most."""
    def rows(offset: int, limit: int) -> list[dict]:
        result = []
        for number in range(offset // per_page + 1, (offset + limit - 1) // per_page + 2):
            chunk = first if number == 1 else fetch(number)
            base = (number - 1) * per_page
            result.extend(chunk[max(0, offset - base):offset + limit - base])
        return decorate(result)
    return rows


def source_page(tokens: dict[str, str] | None = None, installations: list[int] | None = None, *, query: str = "",
                account: str | None = None, provider: str | None = None, page: int = 1, per_page: int = 25) -> dict:
    """One page of analysable repositories, with the total and search by name.

    GitHub is asked only for the visible page (or its search): with thousands of repositories the
    response takes as long as with ten. The App's accounts go in order, concatenated.
    """
    tokens = tokens or {}
    needle = query.strip().casefold()
    segments: list[tuple[int, object]] = []
    statuses: dict[str, dict] = {}
    accounts: list[str] = []
    errors: list[str] = []
    partial = False

    def local(rows: list[dict]) -> None:
        rows = [row for row in rows if not needle or needle in row["name"].casefold()]
        segments.append((len(rows), lambda offset, limit: rows[offset:offset + limit]))

    if installations:
        from pitangus.modules.integrations.github import GitHubAppError, installation_info, repositories_page, search_repositories
        statuses["github"] = {"configured": True, "origin": "github_app"}
        for current in installations:
            try:
                owner = installation_info(current).get("account")
                if isinstance(owner, str):
                    accounts.append(owner)
                if provider not in (None, "github") or (account and account != owner):
                    continue

                def decorate(rows: list[dict], current=current) -> list[dict]:
                    return [{**row, "installation_id": current, "account": row["name"].split("/", 1)[0]} for row in rows]

                if needle:
                    first, total, loading = search_repositories(current, query, 1, per_page)
                    partial = partial or loading
                    fetch = lambda number, current=current: search_repositories(current, query, number, per_page)[0]
                else:
                    first, total = repositories_page(current, 1, per_page)
                    fetch = lambda number, current=current: repositories_page(current, number, per_page)[0]
                segments.append((total, _paged(first, fetch, per_page, decorate)))
            except GitHubAppError as exc:
                errors.append(msg("sources.errors.installation", id=current, detail=exc.message))
    for name in ENABLED_PROVIDERS:
        env = TOKEN_SETTINGS[name]
        if name in statuses:
            continue
        origin = "session" if tokens.get(name) else "environment" if settings.is_set(env) else None
        statuses[name] = {"configured": bool(origin), "origin": origin}
        if origin and provider in (None, name) and not account:
            try:
                local(list_repositories(name, tokens.get(name)))
            except SourceError:
                statuses[name]["error"] = msg("sources.errors.list_failed")
    # Each source is asked only for the rows that fall on the requested page.
    total = sum(count for count, _ in segments)
    offset, remaining, sources = (page - 1) * per_page, per_page, []
    for count, rows in segments:
        if remaining <= 0:
            break
        if offset >= count:
            offset -= count
            continue
        take = min(remaining, count - offset)
        try:
            sources.extend(rows(offset, take))
        except Exception as exc:  # GitHubAppError: one failing page doesn't take down the rest
            errors.append(getattr(exc, "message", None) or str(exc))
        remaining -= take
        offset = 0
    if errors:
        statuses.setdefault("github", {"configured": True, "origin": "github_app"})["error"] = _joined(errors)
    return {"sources": sources, "providers": statuses, "total": total, "page": page, "per_page": per_page,
            "partial": partial, "accounts": sorted(set(accounts), key=str.casefold)}


def find_source(tokens: dict[str, str] | None, installations: list[int] | None, source_id: str) -> dict | None:
    """One specific repository, validated against its credential without listing the whole catalogue.

    Accepts the name-based identifier (`github:owner/repo`) or the stable identity (`github#123`)."""
    if not isinstance(source_id, str):
        return None
    if installations and (source_id.startswith("github:") or source_id.startswith("github#")):
        from pitangus.modules.integrations.github import GitHubAppError, installation_info, installation_repository, installation_repository_by_uid
        owner = source_id.removeprefix("github:").split("/", 1)[0].casefold() if source_id.startswith("github:") else None
        for current in installations:
            try:
                account = installation_info(current).get("account")
                if owner and isinstance(account, str) and account.casefold() != owner:
                    continue
                entry = (installation_repository(current, source_id) if owner is not None
                         else installation_repository_by_uid(current, source_id))
            except GitHubAppError:
                continue
            if entry:
                return {**entry, "installation_id": current, "account": entry["name"].split("/", 1)[0]}
        return None
    provider = source_id.partition(":")[0]
    if provider not in ENABLED_PROVIDERS:
        return None
    try:
        return next((item for item in list_repositories(provider, (tokens or {}).get(provider)) if item["id"] == source_id), None)
    except SourceError:
        return None


def _safe_name(name: str) -> Path | None:
    if name.startswith("/") or "\\" in name:
        return None
    parts = PurePosixPath(name).parts
    if len(parts) < 2:
        return None
    relative = parts[1:]
    if any(part in ("", ".", "..") or part in NOT_CONTENT for part in relative):
        return None
    if any(part.startswith(".") and not _dot_allowed(part, last=index == len(relative) - 1)
           for index, part in enumerate(relative)):
        return None
    return Path(*relative)


def _secret_only_name(name: str) -> Path | None:
    """The relative path of an archive member the shared snapshot doesn't take by its name (a hidden folder or file,
    version control folders other than `.git`): the secret scanners read it apart. None for a name no file can be
    written under (absolute, `..`, a `.git` folder git itself never commits)."""
    if name.startswith("/") or "\\" in name:
        return None
    relative = PurePosixPath(name).parts[1:]
    if not relative or any(part in ("", ".", "..", ".git") for part in relative):
        return None
    return Path(*relative)


def _dot_allowed(part: str, *, last: bool) -> bool:
    """CI/CD folders and, as the last path segment, their files."""
    name = part.lower()
    if not last:
        return name in DOT_FOLDERS
    return name in DOT_FILES


CREDENTIALS_SUFFIX = ".credentials"
SECRET_FILES = "files"


def secrets_root(snapshot: Path) -> Path:
    """Where the files only the secret scanners read are: credential files, and the dependency and build output folders
    the other engines don't read (`set_apart`). Next to the snapshot, so they go away with it, and removed as soon as the
    secret scanners finish (scanning/repository.py). One folder down from `secrets_scan_root`, which holds nothing else."""
    return secrets_scan_root(snapshot) / SECRET_FILES


def secrets_scan_root(snapshot: Path) -> Path:
    """The folder Betterleaks scans for `secrets_root`: no committed file sits at its top, where Betterleaks loads its
    control files (`.gitleaksignore`, `.betterleaksignore`) whatever its flags say. The repository's own are honoured
    and declared by Pitangus instead (scanning/engines.py, `_ignore_file_allowed`), never silently by the engine."""
    return snapshot.with_name(snapshot.name + CREDENTIALS_SUFFIX)



def credential_path(parts: tuple[str, ...]) -> Path | None:
    """The relative path of a credential file (by its name: `.env*`, `.npmrc`, `id_rsa`, `credentials`…) anywhere in the
    repository, dot folders included (`.aws/credentials`); never in version control metadata (`.git`)."""
    if not parts or any(part in ("", ".", "..") or part in NOT_CONTENT for part in parts):
        return None
    name = parts[-1].lower()
    # SSH keys go by `id_<type>[_<purpose>]` with no extension (`id_ed25519_deploy`); `id_utils.py` is code.
    ssh_key = name.startswith("id_") and "." not in name
    return Path(*parts) if name in SECRET_NAMES or name.startswith(".env") or ssh_key else None


def apart_reason(parts: tuple[str, ...], index: int, manifests: set[str], maps: set[str]) -> str | None:
    """Why the folder `parts[:index + 1]` is read by the secret scanners only, or None. `dependencies`: one that package
    managers install into or vendor (`node_modules`, `vendor`), wherever it is. `generated`: a build output folder (`dist`,
    `build`, `target`…) at the repository root, next to a build manifest (`packages/web/dist` beside
    `packages/web/package.json`), or holding source maps. Elsewhere (`src/build`, `src/data`) a folder is source.
    `manifests`: the folders holding a manifest; `maps`: the folders under which a `.map` file is (both as posix paths,
    "" for the root)."""
    folder = parts[index].lower()
    if folder in DEPENDENCY_FOLDERS:
        return "dependencies"
    if folder not in OUTPUT_FOLDERS:
        return None
    parent, own = "/".join(parts[:index]), "/".join(parts[:index + 1])
    return "generated" if index == 0 or parent in manifests or own in maps else None


def set_apart(root: Path, maps_seen: set[str] | None = None) -> dict[str, str]:
    """Moves the dependency and build output folders of a snapshot (`apart_reason`) to `secrets_root`, where only the
    secret scanners read them. Returns {folder + "/": reason}, the outermost folder of each. `maps_seen`: the source
    maps of the repository (no engine reads them, so they aren't in the snapshot), by relative path."""
    files = sorted(path.relative_to(root) for path in root.rglob("*") if path.is_file() and not path.is_symlink())
    manifests = {path.parent.as_posix() if path.parent != Path(".") else "" for path in files if is_manifest(path)}
    maps = {"/".join(PurePosixPath(path).parts[:end]) for path in maps_seen or () for end in range(1, len(PurePosixPath(path).parts))}
    apart: dict[str, str] = {}
    for relative in files:
        parts = relative.parts
        for index in range(len(parts) - 1):
            folder = "/".join(parts[:index + 1]) + "/"
            if folder in apart:
                reason = apart[folder]
            elif reason := apart_reason(parts, index, manifests, maps):
                apart[folder] = reason
            if reason:
                target = secrets_root(root) / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                (root / relative).replace(target)
                break
    for folder in sorted(apart, key=lambda item: -item.count("/")):
        shutil.rmtree(root / folder, ignore_errors=True)
    return dict(sorted(apart.items()))


def _analyzable(relative: Path) -> bool:
    name = relative.name.lower()
    if name in SOURCE_NAMES or is_manifest(relative):
        return True
    return relative.suffix.lower() in SOURCE_SUFFIXES or relative.suffix.lower() in TEXT_SUFFIXES


def _left_out(stats: dict, relative: Path | str, reason: str = "left_out") -> None:
    """A committed file the snapshot couldn't take (too large, over budget, a name no file can be written under, a link):
    listed with why, all of them, so that a finding the engines saw there before isn't taken as fixed. A long list is
    declared by folder when the snapshot is done (`_declared`), never cut."""
    stats["unexamined"].setdefault(relative if isinstance(relative, str) else relative.as_posix(), reason)


def _declared(stats: dict, files) -> None:
    """The run's list of what the snapshot left out, as units (coverage_units.compact): by path up to UNEXAMINED_MAX,
    by folder beyond it."""
    stats["unexamined"] = coverage_units.compact(files, stats["unexamined"], UNEXAMINED_MAX)


def _member_path(name: str) -> str:
    """An archive member's path in the repository (without the archive's top folder), as the provider wrote it."""
    return "/".join(name.lstrip("/").split("/")[1:])


def as_text(root: Path) -> int:
    """Rewrites as UTF-8 every file of a snapshot (and of the copy only the secret scanners read) whose bytes are a
    consistent UTF-16 or UTF-32 text (shared/encodings.as_utf8): the engines read bytes, and a token written two or four
    bytes per character is where none of their patterns looks. Same lines, same characters. Returns how many."""
    count = 0
    for folder in (root, secrets_root(root)):
        if not folder.is_dir():
            continue
        for path in folder.rglob("*"):
            if not path.is_file() or path.is_symlink():
                continue
            with path.open("rb") as handle:   # only a file whose start says UTF-16 or UTF-32 is read whole
                if (encodings.codec(handle.read(encodings.SAMPLE)) or "utf-8").startswith("utf-8"):
                    continue
            converted = encodings.as_utf8(path.read_bytes())
            if converted is not None:
                path.write_bytes(converted)
                count += 1
    return count


def _write_credential(root: Path, relative: Path, content: bytes, stats: dict) -> None:
    target = secrets_root(root) / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(content)
    stats["credential_files"] = stats.get("credential_files", 0) + 1


def _write_secret_only(root: Path, relative: Path, content: bytes, stats: dict) -> None:
    """A committed file only the secret scanners read (`secrets_root`): the code engines don't read it."""
    target = secrets_root(root) / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(content)
    stats["secret_only"] = stats.get("secret_only", 0) + 1
    stats["secret_only_bytes"] = stats.get("secret_only_bytes", 0) + len(content)


def _secret_only_fits(stats: dict, size: int) -> bool:
    """Whether a file only the secret scanners read fits: its own size and the budget of that copy. One that doesn't is
    left out and listed (`_left_out`), and the snapshot is then truncated if it was the budget."""
    if size > MAX_FILE:
        stats["skipped_too_large"] = stats.get("skipped_too_large", 0) + 1
        return False
    if stats.get("secret_only", 0) >= MAX_FILES or stats.get("secret_only_bytes", 0) + size > SECRET_ONLY_MAX_TOTAL:
        stats["skipped_over_budget"] = stats.get("skipped_over_budget", 0) + 1
        stats["truncated"] = True
        return False
    return True


def _extract_limited(blob: bytes | Path, root: Path, tree: dict[str, str] | None = None) -> dict:
    """Copies what fits and returns counts of what was left out. `tree`: what the commit holds ({path: kind}), whose
    entries the archive didn't bring are declared (`declare_committed`).

    Exceeding the limits is not an error: a large repository is partly analysed
    and the run states exactly what was not looked at. Failing would leave the
    user with nothing, and silently analysing 10 % would be worse still.
    """
    stats: dict = {"files": 0, "bytes": 0, "skipped_not_analyzable": 0, "skipped_too_large": 0,
                   "skipped_over_budget": 0, "truncated": False, "unexamined": {}, "credential_files": 0}
    maps: set[str] = set()
    listed: list[str] = []
    total = 0
    count = 0
    expanded = 0
    try:
        archive = (tarfile.open(name=str(blob), mode="r:gz") if isinstance(blob, Path)
                   else tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz"))
        with archive:
            for member in archive:
                if member.issym() or member.islnk():
                    # A link is committed as its target's path: nothing an engine reads, and never followed.
                    if path := _member_path(member.name):
                        listed.append(path)
                        _left_out(stats, path, "symlink")
                    continue
                if not member.isfile():
                    continue
                # Defence against malicious decompression: a small tarball can declare
                # terabytes. The declared size is checked before reading anything.
                expanded += member.size
                if expanded > MAX_EXPANSION:
                    raise SourceError(msg("sources.errors.decompression_bomb"))
                listed.append(_member_path(member.name))
                if member.name.startswith("/") or "\\" in member.name:
                    # Committed under a name no file here can be written under (`a\\b.py`): left out, and said.
                    _left_out(stats, _member_path(member.name), "unwritable_name")
                    continue
                credential = credential_path(PurePosixPath(member.name).parts[1:])
                if credential is not None:
                    source = archive.extractfile(member) if member.size <= MAX_FILE else None
                    if source is None:
                        stats["skipped_too_large"] += 1
                        _left_out(stats, credential)
                        continue
                    _write_credential(root, credential, source.read(MAX_FILE + 1), stats)
                    continue
                relative = _safe_name(member.name)
                apart = None
                if relative is None:
                    apart = _secret_only_name(member.name)
                    if apart is None:
                        _left_out(stats, _member_path(member.name), "unwritable_name")
                        continue
                elif not _analyzable(relative):
                    stats["skipped_not_analyzable"] += 1
                    if relative.suffix.lower() == ".map":
                        maps.add(relative.as_posix())
                    apart = relative
                if apart is not None:
                    source = archive.extractfile(member) if _secret_only_fits(stats, member.size) else None
                    if source is None:
                        _left_out(stats, apart)
                        continue
                    _write_secret_only(root, apart, source.read(MAX_FILE + 1), stats)
                    continue
                # Code over 2 MB is almost always generated; a manifest isn't, so it has its own limit.
                limit = MAX_MANIFEST if is_manifest(relative) else MAX_FILE
                if member.size > limit:
                    stats["skipped_too_large"] += 1
                    _left_out(stats, relative)
                    continue
                if count >= MAX_FILES or total + member.size > MAX_TOTAL:
                    stats["skipped_over_budget"] += 1
                    stats["truncated"] = True
                    _left_out(stats, relative)
                    continue
                source = archive.extractfile(member)
                if source is None:
                    continue
                content = source.read(limit + 1)
                if len(content) != member.size:
                    raise SourceError(msg("sources.errors.invalid_archive_file"))
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(content)
                total += len(content)
                count += 1
    except (tarfile.TarError, OSError) as exc:
        raise SourceError(msg("sources.errors.invalid_archive")) from exc
    stats["files"] = count
    stats["bytes"] = total
    stats["archive_bytes"] = expanded
    stats["apart"] = set_apart(root, maps)
    stats["transcoded"] = as_text(root)
    if tree is not None:
        declare_committed(stats, tree, root)
    _declared(stats, [path for path in tree if not path.endswith("/")] if tree is not None else listed)
    return stats


LOCAL_ONLY_SHOWN = 20


def snapshot_directory(source: Path, destination: Path, *, committed: bool = False, tree: dict[str, str] | None = None) -> dict:
    """Read-only copy of a local folder with the same filters as a remote repository.

    No symlinks (nothing escapes the folder), no version control metadata, and the same limits: code up to 2 MB per file,
    manifests and lockfiles up to 64 MB. `committed`: the folder holds exactly what git has (a commit or the index);
    otherwise it's a folder on disk, and what tools install or cache there (`LOCAL_ONLY`) is left out and named. `tree`:
    the commit's or the index's entries ({path: kind}), whose ones the copy doesn't hold are declared (`declare_committed`)."""
    total = count = 0
    truncated = False
    stats: dict = {"unexamined": {}, "credential_files": 0, "skipped_too_large": 0, "skipped_over_budget": 0}
    seen: list[str] = []
    skipped = {"not_analyzable": 0}
    local_only: list[str] = []
    maps: set[str] = set()
    # From git, `.hg` or `.svn` folders were committed like any other: only `.git` is never content.
    metadata = {".git"} if committed else NOT_CONTENT
    for directory, folders, filenames in os.walk(source, followlinks=False):
        # Dot folders are walked too: their credential files (`.aws/credentials`) and, when committed, everything else
        # in them goes to the secret scanners; only pipelines enter the shared snapshot.
        kept = []
        for folder in folders:
            if folder in metadata or (Path(directory) / folder).is_symlink():
                continue
            if not committed and folder in LOCAL_ONLY:
                local_only.append((Path(directory) / folder).relative_to(source).as_posix() + "/")
                continue
            kept.append(folder)
        folders[:] = kept
        for filename in filenames:
            path = Path(directory) / filename
            if path.is_symlink() or not path.is_file():
                continue
            relative = path.relative_to(source)
            seen.append(relative.as_posix())
            if credential_path(relative.parts) is not None:
                if path.stat().st_size > MAX_FILE:
                    stats["skipped_too_large"] += 1
                    _left_out(stats, relative)
                else:
                    _write_credential(destination, relative, path.read_bytes(), stats)
                continue
            size = path.stat().st_size
            hidden = any(part.startswith(".") and not _dot_allowed(part, last=index == len(relative.parts) - 1)
                         for index, part in enumerate(relative.parts))
            if hidden and not committed:
                continue
            if not hidden and not _analyzable(relative):
                skipped["not_analyzable"] += 1
                if relative.suffix.lower() == ".map":
                    maps.add(relative.as_posix())
            if hidden or not _analyzable(relative):
                if _secret_only_fits(stats, size):
                    _write_secret_only(destination, relative, path.read_bytes(), stats)
                else:
                    _left_out(stats, relative)
                continue
            if size > (MAX_MANIFEST if is_manifest(relative) else MAX_FILE):
                stats["skipped_too_large"] += 1
                _left_out(stats, relative)
                continue
            if count >= MAX_FILES or total + size > MAX_TOTAL:
                stats["skipped_over_budget"] += 1
                truncated = True
                _left_out(stats, relative)
                continue
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            content = path.read_bytes()
            target.write_bytes(content)
            total += len(content)
            count += 1
    # The same counters as a downloaded archive (_extract_limited): the snapshot step says what was left out and why.
    apart = set_apart(destination, maps)
    transcoded = as_text(destination)
    if tree is not None:
        declare_committed(stats, tree, destination)
    _declared(stats, [path for path in tree if not path.endswith("/")] if tree is not None else seen)
    return {"files": count, "bytes": total, "skipped_not_analyzable": skipped["not_analyzable"],
            "skipped_too_large": stats["skipped_too_large"], "skipped_over_budget": stats["skipped_over_budget"],
            "truncated": truncated or bool(stats.get("truncated")), "unexamined": stats["unexamined"],
            "credential_files": stats["credential_files"], "secret_only": stats.get("secret_only", 0),
            "apart": apart, "transcoded": transcoded, **({"committed": stats["committed"]} if stats.get("committed") else {}),
            **({"local_only": sorted(local_only)[:LOCAL_ONLY_SHOWN], "local_only_count": len(local_only)} if local_only else {})}


def snapshot_source(source_id: str, destination: Path, tokens: dict[str, str] | None = None,
                    installation_id: int | None = None, ref: str | None = None, progress=None) -> tuple[Path, dict]:
    """Read-only snapshot. `ref` pins a specific commit (PR review); GitHub only."""
    if ref is not None and (not re.fullmatch(r"[0-9a-f]{40}", ref) or not source_id.startswith("github:")):
        raise SourceError(msg("sources.errors.invalid_commit"))
    if not re.fullmatch(r"(?:github:[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+|gitlab:[0-9]+)", source_id):
        raise SourceError(msg("sources.errors.invalid_repository"))
    provider = source_id.partition(":")[0]
    if reason := unavailable(provider):
        raise SourceError(reason)
    if provider == "github" and installation_id is not None:
        from pitangus.modules.integrations.github import GitHubAppError, installation_repository, installation_token
        try:
            selected = installation_repository(installation_id, source_id)
            token = installation_token(installation_id)
        except GitHubAppError as exc:
            raise SourceError(exc.message) from exc
    else:
        token = (tokens or {}).get(provider) or settings.text(TOKEN_SETTINGS[provider])
        entries = list_repositories(provider, token)
        selected = next((entry for entry in entries if entry["id"] == source_id), None)
    if selected is None:
        raise SourceError(msg("sources.errors.not_available"))
    if not token:
        raise SourceError(msg("sources.errors.connect_first"))
    archive_path = destination.parent / "repository.tar.gz"
    if provider == "github":
        name = source_id.removeprefix("github:")
        # The commit first: the archive and the list of what it holds are then both of that one commit.
        commit = ref or _github_commit(name, selected.get("branch") or "HEAD", token)
        url = f"https://api.github.com/repos/{name}/tarball/{commit}"
        _download_archive(url, token, provider, archive_path, redirect_host="codeload.github.com", progress=progress)
    else:
        identifier = source_id.removeprefix("gitlab:")
        commit = _gitlab_commit(identifier, selected.get("branch") or "HEAD", token)
        url = (f"https://gitlab.com/api/v4/projects/{quote(identifier)}/repository/archive.tar.gz"
               f"?sha={commit}&include_lfs_blobs=false")
        _download_archive(url, token, provider, archive_path, progress=progress)
    try:
        tree = _github_tree(name, commit, token) if provider == "github" else _gitlab_tree(identifier, commit, token)
        stats = _extract_limited(archive_path, destination, tree)
    finally:
        archive_path.unlink(missing_ok=True)
    selected["files"] = stats["files"]
    selected["commit"] = commit
    selected["snapshot"] = stats
    return destination, selected


# --- What the commit holds -----------------------------------------------------------------------------------------
# The provider's archive is `git archive`: it leaves out what `.gitattributes` marks `export-ignore`, a submodule's
# files, and an LFS object (only its pointer comes). What was committed is the commit's tree, listed by the provider's
# API (or by `git ls-tree` for a local repository): everything in it that the snapshot doesn't hold as committed is
# declared unexamined with why, whatever made the archive leave it out.

def _json_request(url: str, token: str, provider: str) -> object:
    try:
        return json.loads(_request(url, token, provider))
    except (ValueError, UnicodeDecodeError) as exc:
        raise SourceError(msg("sources.errors.invalid_data")) from exc


def _commit(value: object) -> str:
    commit = value.strip() if isinstance(value, str) else ""
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise SourceError(msg("sources.errors.invalid_commit"))
    return commit


def _github_commit(name: str, ref: str, token: str) -> str:
    try:
        body = _request(f"https://api.github.com/repos/{name}/commits/{quote(ref, safe='')}", token, "github",
                        accept="application/vnd.github.sha")
        return _commit(body.decode("ascii", errors="replace"))
    except SourceError:
        raise
    except Exception as exc:  # a body that isn't a commit
        raise SourceError(msg("sources.errors.invalid_commit")) from exc


def _gitlab_commit(identifier: str, ref: str, token: str) -> str:
    found = _json_request(f"https://gitlab.com/api/v4/projects/{quote(identifier)}/repository/commits/{quote(ref, safe='')}", token, "gitlab")
    return _commit(found.get("id") if isinstance(found, dict) else None)


def _kind(entry: dict) -> str | None:
    """A tree entry as what a snapshot holds of it: a file, a link, a submodule; None for a folder."""
    kind, mode = str(entry.get("type") or ""), str(entry.get("mode") or "")
    if kind == "commit" or mode == "160000":
        return "submodule"
    if kind == "blob":
        return "symlink" if mode == "120000" else "file"
    return None


GIT_OBJECT = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")   # a SHA-1 or SHA-256 object name


def _github_tree(name: str, commit: str, token: str) -> dict[str, str]:
    """{path: kind} of every entry of the commit's tree (a folder's path ends in "/"). A tree the API truncates is
    walked folder by folder; one still unlisted after TREE_REQUESTS is listed as itself, `unlisted`."""
    budget = [TREE_REQUESTS]

    def fetch(sha: str, recursive: bool) -> dict:
        budget[0] -= 1
        found = _json_request(f"https://api.github.com/repos/{name}/git/trees/{sha}" + ("?recursive=1" if recursive else ""), token, "github")
        if not isinstance(found, dict) or not isinstance(found.get("tree"), list):
            raise SourceError(msg("sources.errors.invalid_data"))
        return found

    tree: dict[str, str] = {}

    def walk(sha: str, prefix: str) -> None:
        if budget[0] <= 0:
            tree[prefix or "./"] = "unlisted"
            return
        found = fetch(sha, recursive=True)
        if not found.get("truncated"):
            for entry in found["tree"]:
                if isinstance(entry, dict) and isinstance(entry.get("path"), str) and (kind := _kind(entry)):
                    tree[prefix + entry["path"]] = kind
            return
        if budget[0] <= 0:
            tree[prefix or "./"] = "unlisted"
            return
        for entry in fetch(sha, recursive=False)["tree"]:
            if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
                continue
            if entry.get("type") == "tree" and isinstance(entry.get("sha"), str):
                if not GIT_OBJECT.fullmatch(entry["sha"]):
                    # It goes into the next request's URL: only an object name, never whatever the response says.
                    raise SourceError(msg("sources.errors.invalid_data"))
                walk(entry["sha"], f"{prefix}{entry['path']}/")
            elif kind := _kind(entry):
                tree[prefix + entry["path"]] = kind

    walk(commit, "")
    return tree


GITLAB_TREE_PAGES = 2_000


def _gitlab_tree(identifier: str, commit: str, token: str) -> dict[str, str]:
    tree: dict[str, str] = {}
    for page in range(1, GITLAB_TREE_PAGES + 1):
        rows = _json_request(f"https://gitlab.com/api/v4/projects/{quote(identifier)}/repository/tree?recursive=true"
                             f"&ref={commit}&per_page=100&page={page}", token, "gitlab")
        if not isinstance(rows, list):
            raise SourceError(msg("sources.errors.invalid_list"))
        for entry in rows:
            if isinstance(entry, dict) and isinstance(entry.get("path"), str) and (kind := _kind(entry)):
                tree[entry["path"]] = kind
        if len(rows) < 100:
            return tree
    tree["./"] = "unlisted"
    return tree


def lfs_pointer(data: bytes) -> bool:
    """Whether a committed file's content is a Git LFS pointer, by the pointer's specification: `key value` lines,
    `version` first, an `oid` and a `size`. The file it stands for is elsewhere."""
    if len(data) >= LFS_POINTER_MAX or not data.endswith(b"\n"):
        return False
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        return False
    keys = [line.partition(" ")[0] for line in lines]
    return bool(lines) and keys[0] == "version" and "oid" in keys and "size" in keys and all(" " in line for line in lines)


TREE_REASONS = {"submodule": "submodule", "symlink": "symlink", "unlisted": "tree_unlisted"}


def declare_committed(stats: dict, tree: dict[str, str], root: Path) -> None:
    """Every entry of the commit's tree (`tree`, {path: kind}) the snapshot doesn't hold as committed, declared
    unexamined in `stats` with why: a submodule (its folder), a link, a folder the provider didn't list, a file the
    archive doesn't hold (`not_in_archive`: `export-ignore`, or anything else that left it out), a Git LFS pointer whose
    object wasn't fetched (`lfs_object`). `stats["committed"]`: how many of each."""
    held = {path.relative_to(folder).as_posix(): path for folder in (root, secrets_root(root)) if folder.is_dir()
            for path in folder.rglob("*") if path.is_file() and not path.is_symlink()}
    counted: dict[str, int] = {}
    for path, kind in tree.items():
        if path in stats["unexamined"]:
            continue
        if kind in TREE_REASONS:
            reason = TREE_REASONS[kind]
            if kind == "submodule":   # its path, and everything under it
                _left_out(stats, path.rstrip("/") + "/", reason)
        elif path not in held:
            reason = "not_in_archive"
        elif held[path].stat().st_size < LFS_POINTER_MAX and lfs_pointer(held[path].read_bytes()):
            reason = "lfs_object"
        else:
            continue
        _left_out(stats, path, reason)
        counted[reason] = counted.get(reason, 0) + 1
    if counted:
        stats["committed"] = dict(sorted(counted.items()))
