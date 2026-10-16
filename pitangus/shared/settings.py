"""Every setting Pitangus reads from the environment, declared in one place.

Values are read when asked for (tests and the CLI change the environment at run time), and `problems()` checks them
all once at start-up, so a typo stops the server with a clear message instead of failing later. Reading a setting
that isn't declared here is a programming error.
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import os
from collections.abc import Mapping
from dataclasses import dataclass
from urllib.parse import urlsplit

from pitangus.shared.i18n import msg

TRUE, FALSE = ("1", "true", "yes", "on"), ("0", "false", "no", "off", "")


@dataclass(frozen=True)
class Setting:
    default: str = ""
    kind: str = "text"  # text, flag, integer, choice, url, urls, key, token, addresses
    choices: tuple[str, ...] = ()
    minimum: int | None = None
    required: bool = False


SETTINGS: dict[str, Setting] = {
    # Where things are
    "PITANGUS_DATABASE_URL": Setting(required=True),
    "PITANGUS_DATA_DIR": Setting(),
    "PITANGUS_CONFIG_DIR": Setting(),
    # How the panel is reached
    "PITANGUS_PUBLIC_URL": Setting(kind="url"),
    "PITANGUS_ALLOWED_ORIGINS": Setting(kind="urls"),
    "PITANGUS_ALLOW_INSECURE_HTTP": Setting(kind="flag"),
    "PITANGUS_BIND": Setting(default="127.0.0.1"),
    "PITANGUS_FORWARDED_ALLOW_IPS": Setting(),
    "PITANGUS_TLS_CERT": Setting(),
    "PITANGUS_TLS_KEY": Setting(),
    "PITANGUS_EMBEDDED_WORKER": Setting(default="1", kind="flag"),
    # Keys and tokens
    "PITANGUS_MASTER_KEY": Setting(kind="key"),
    "PITANGUS_PREVIOUS_MASTER_KEY": Setting(kind="key"),  # the key before a rotation: secrets keep their identity
    "PITANGUS_SESSION_KEY": Setting(kind="key"),
    "PITANGUS_METRICS_TOKEN": Setting(kind="token"),
    "PITANGUS_CRON_TOKEN": Setting(kind="token"),
    "CRON_SECRET": Setting(kind="token"),  # what Vercel Cron sends; accepted as the cron token
    "PITANGUS_IMPORT_TOKEN": Setting(kind="token"),  # CI uploading SARIF (POST /api/ci/sarif, `import-sarif --server`)
    "PITANGUS_REQUIRE_TOTP": Setting(default="admins", kind="choice", choices=("admins", "all", "none")),
    # Behaviour
    "PITANGUS_DEFAULT_LOCALE": Setting(default="en", kind="choice", choices=("en", "es")),
    "PITANGUS_LOG_LEVEL": Setting(default="INFO", kind="choice", choices=("DEBUG", "INFO", "WARNING", "ERROR")),
    "PITANGUS_LOG_FORMAT": Setting(default="text", kind="choice", choices=("text", "json")),
    "PITANGUS_LOG_FILE": Setting(),
    "PITANGUS_ENGINE_RUNNER": Setting(default="auto", kind="choice", choices=("auto", "docker", "local")),
    "PITANGUS_PERIODIC": Setting(default="leader", kind="choice", choices=("leader", "external")),
    "PITANGUS_PR_POLL_SECONDS": Setting(default="300", kind="integer", minimum=60),
    "PITANGUS_BRANCH_MIN_MINUTES": Setting(default="60", kind="integer", minimum=10),
    "PITANGUS_ADVISORY_WATCH_HOURS": Setting(default="24", kind="integer", minimum=0),
    "PITANGUS_DOWNLOAD_TIMEOUT": Setting(default="900", kind="integer", minimum=60),
    "PITANGUS_CVE_SYNC": Setting(default="on", kind="flag"),
    "PITANGUS_EUVD": Setting(default="on", kind="flag"),
    "PITANGUS_NVD_API_KEY": Setting(),
    "PITANGUS_ALLOW_PRIVATE_REGISTRIES": Setting(kind="flag"),
    "PITANGUS_ALLOW_PRIVATE_WEBHOOKS": Setting(kind="flag"),
    # How a scan proves it looked (docs/findings.md): `on` (the default since 0.14) fixes only what the owner engine
    # proved gone where it looked, with per-file coverage, unseen findings and the fix hold; `shadow` works them out
    # without changing the registry, records how they would and fixes as before. An engine run that broke its contract
    # opens and fixes nothing in every mode
    "PITANGUS_COVERAGE_MODE": Setting(default="on", kind="choice", choices=("off", "shadow", "on")),
    # Finding identity: `v2` (the default since 0.14) one finding per family of identical problems, by the canonical
    # identity; `shadow` the engines' fingerprints, also working out the identity and recording the differences; `v1` the
    # engines' fingerprints only
    "PITANGUS_IDENTITY_MODE": Setting(default="v2", kind="choice", choices=("v1", "shadow", "v2")),
    # Betterleaks asks each secret's provider whether it is still active (network requests carrying the secret): off
    # unless enabled; it reorders priorities, never hides a finding
    "PITANGUS_SECRET_VALIDATION": Setting(kind="flag"),
    # What the scanned repository says to suppress an engine's results (scanning/repo_controls.py): comments in the code
    # (`gitleaks:allow`, `# zizmor: ignore[…]`, `trivy:ignore`, `checkov:skip=`, `nosemgrep`) and files an engine would
    # load (`.gitleaksignore`, `.github/zizmor.yml`, `.trivyignore`, `.checkov.yaml`, `osv-scanner.toml`). Off, they are
    # honoured and every result they suppress is declared, excluded with its file and line; on, they suppress nothing
    "PITANGUS_IGNORE_REPO_SUPPRESSIONS": Setting(kind="flag"),
    # Its name before 0.14.1, when it covered the secret engines only: still read, with the same meaning
    "PITANGUS_SECRETS_IGNORE_INLINE_ALLOW": Setting(kind="flag"),
    # A scan that would fix at least this share (%) of an asset's open findings, and at least this many, holds the fixes
    # until the next complete scan confirms them
    "PITANGUS_FIX_HOLD_PERCENT": Setting(default="30", kind="integer", minimum=1),
    "PITANGUS_FIX_HOLD_MINIMUM": Setting(default="10", kind="integer", minimum=1),
    # After this many scans without being able to check an open finding, the panel warns about it
    "PITANGUS_UNSEEN_WARN_SCANS": Setting(default="3", kind="integer", minimum=1),
    # Which analysis engines run (scanning/engine_switches.py). An administrator turns each on or off in the panel
    # (Settings → Analysis engines); one of these set here wins and locks that switch. Unset, the panel's choice applies,
    # else the default: every engine on but Checkov, Grype and the full web scan (ZAP, katana, subfinder), which is
    # experimental. Off, an engine is "not run (disabled)": what it found before stays open, never fixed
    "PITANGUS_DAST_ENABLED": Setting(kind="flag"),
    "PITANGUS_CHECKOV_ENABLED": Setting(kind="flag"),
    "PITANGUS_GRYPE_ENABLED": Setting(kind="flag"),
    "PITANGUS_OPENGREP_ENABLED": Setting(default="on", kind="flag"),
    "PITANGUS_BETTERLEAKS_ENABLED": Setting(default="on", kind="flag"),
    "PITANGUS_TRIVY_ENABLED": Setting(default="on", kind="flag"),
    "PITANGUS_OSV_SCANNER_ENABLED": Setting(default="on", kind="flag"),
    "PITANGUS_ZIZMOR_ENABLED": Setting(default="on", kind="flag"),
    "PITANGUS_HTTPX_ENABLED": Setting(default="on", kind="flag"),
    "PITANGUS_TESTSSL_ENABLED": Setting(default="on", kind="flag"),
    "PITANGUS_NUCLEI_ENABLED": Setting(default="on", kind="flag"),
    "PITANGUS_KATANA_ENABLED": Setting(default="on", kind="flag"),
    # GitLab's sast-rules (MIT and Apache-2.0 ones, third_party/gitlab-sast-rules) next to Pitangus' own rules: off, since
    # on the measured corpus none reached 85% precision with at least 3 hits
    "PITANGUS_THIRD_PARTY_RULES": Setting(kind="flag"),
    # Pitangus' Opengrep rules that start off (`opt_in` in rules/*.yml, measured too noisy to be on by default) to turn on,
    # comma-separated ids (`appsec.js.dom-xss-sink`)
    "PITANGUS_SAST_OPT_IN_RULES": Setting(),
    # The public addresses (or CIDR ranges) web scans leave from, comma-separated: the panel tells site owners to allow them
    "PITANGUS_EGRESS_IPS": Setting(kind="addresses"),
    # Engines started through the Docker socket mount folders by their path on the host
    "PITANGUS_HOST_DATA_DIR": Setting(),
    "PITANGUS_HOST_RULES_DIR": Setting(),
    # Integrations configured by the server instead of the panel
    "GITHUB_APP_ID": Setting(),
    "GITHUB_APP_SLUG": Setting(),
    "GITHUB_APP_PRIVATE_KEY_FILE": Setting(),
    "GITHUB_TOKEN": Setting(),
    "GITLAB_TOKEN": Setting(),
    "OPENAI_API_KEY": Setting(),
    "ANTHROPIC_API_KEY": Setting(),
    # Tests only: one PostgreSQL schema per data folder
    "PITANGUS_DB_ISOLATE": Setting(kind="choice", choices=("", "data-dir")),
}


def _raw(name: str) -> str:
    setting = SETTINGS[name]  # KeyError: declare it above first
    return os.environ.get(name, "").strip() or setting.default


def text(name: str) -> str:
    return _raw(name)


def flag(name: str) -> bool:
    return _raw(name).lower() in TRUE


def integer(name: str) -> int:
    setting = SETTINGS[name]
    try:
        value = int(_raw(name))
    except ValueError:
        value = int(setting.default)
    return max(setting.minimum, value) if setting.minimum is not None else value


def items(name: str) -> list[str]:
    return [item.strip().rstrip("/") for item in _raw(name).split(",") if item.strip()]


ADDRESSES_LIMIT = 16


def _addresses(value: str) -> list[str]:
    entries = [item.strip() for item in value.split(",") if item.strip()]
    if len(entries) > ADDRESSES_LIMIT:
        raise ValueError(f"at most {ADDRESSES_LIMIT} entries")
    shown: list[str] = []
    for entry in entries:
        network = ipaddress.ip_network(entry, strict=False)
        written = str(network.network_address) if network.num_addresses == 1 else str(network)
        if written not in shown:
            shown.append(written)
    return shown


def addresses(name: str) -> list[str]:
    """IP addresses or CIDR ranges, normalized and without repeats; none if the value is invalid (start-up refuses it)."""
    try:
        return _addresses(_raw(name))
    except ValueError:
        return []


def is_set(name: str) -> bool:
    return bool(os.environ.get(name, "").strip())


def _url_problem(name: str, value: str):
    parts = urlsplit(value)
    if parts.scheme not in ("http", "https") or not parts.hostname or parts.path not in ("", "/") or parts.query:
        return msg("cli.settings.invalid_url", name=name, value=value)
    return None


def _check(name: str, setting: Setting, environment: Mapping[str, str]):
    value = environment.get(name, "").strip()
    if not value:
        return msg("cli.settings.missing", name=name) if setting.required else None
    if setting.kind == "flag" and value.lower() not in TRUE + FALSE:
        return msg("cli.settings.invalid_flag", name=name, value=value)
    if setting.kind == "integer":
        try:
            number = int(value)
        except ValueError:
            return msg("cli.settings.invalid_integer", name=name, value=value)
        if setting.minimum is not None and number < setting.minimum:
            return msg("cli.settings.below_minimum", name=name, value=value, minimum=setting.minimum)
    if setting.kind == "choice" and value not in setting.choices and value.lower() not in setting.choices \
            and value.upper() not in setting.choices:
        return msg("cli.settings.invalid_choice", name=name, value=value, choices=", ".join(item for item in setting.choices if item))
    if setting.kind == "url":
        return _url_problem(name, value)
    if setting.kind == "urls":
        return next((problem for item in value.split(",") if item.strip()
                     for problem in [_url_problem(name, item.strip().rstrip("/"))] if problem), None)
    if setting.kind == "key":
        try:
            decoded = base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError):
            decoded = b""
        if len(decoded) != 32:
            return msg("cli.settings.invalid_key", name=name)
    if setting.kind == "addresses":
        try:
            _addresses(value)
        except ValueError:
            return msg("cli.settings.invalid_addresses", name=name, value=value[:200], max=ADDRESSES_LIMIT)
    if setting.kind == "token" and len(value) < 32:
        return msg("cli.settings.short_token", name=name)
    return None


def problems(environment: Mapping[str, str] | None = None) -> list[dict]:
    """Every setting that is set but invalid, or required and missing, as messages."""
    environment = os.environ if environment is None else environment
    return [problem for name, setting in SETTINGS.items() if (problem := _check(name, setting, environment))]
