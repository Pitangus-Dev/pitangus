# Changelog

Notable changes to Pitangus (called Tamandua up to 0.11). The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions are `major.minor` in the code (`pitangus/version.py`)
and `major.minor.patch` in the release tags. While Pitangus is in beta (0.x), the API and stored formats may change
between minor versions: anything that changes behaviour is called out below.

## [Unreleased]

### Fixed

- **The audit report's period is now real.** On a repository's state it keeps the findings detected by the end of the
  period and not fixed before it starts, and says so; a single scan outside the period is refused instead of being
  presented as evidence for it. The consolidated report filters the same way.
- **Figures that add up.** Findings out of scope no longer count as in scope; the critical and high figures are the
  open ones in both reports; a single scan no longer shows "0 fixed" (it can't know).
- **Evidence whole.** The revision is the git commit (the snapshot's SHA-256 goes apart, whole), the reference is no
  longer cut, long paths keep their file name and line, and the closing note no longer claims a review nobody signed.
- Smaller fixes: "page X of Y", code shown as code instead of backticks, dependency advisories located at their
  manifest, EPSS with the locale's decimal separator, Spanish agreeing with «hallazgos», and the Markdown export with
  its states translated and its headings nested properly.

### Security

- **The panel and the docs site build with pnpm instead of npm**, pinned by hash through corepack, with supply-chain
  settings in their `pnpm-workspace.yaml`. A release has to be a week old before it is installed, and a recent version
  that loses the provenance its predecessors had is refused. Transitive dependencies can't come from git or tarballs,
  and dependencies' install scripts never run (the way the 2025 npm worms spread). The lockfiles keep npm's versions,
  except that the docs site goes back to astro 7.3.5 and Starlight 0.42.5 (the newer ones came out that same day). A
  security fix younger than a week goes in as an exception for that exact version. `openapi-typescript` is now a pinned
  dev dependency instead of an `npx` download.
- **Vite 8.3.3 in the panel's development server** (GHSA-9jrq-w75r-8gcw, GHSA-vfpm-58rq-9qcg, GHSA-rq7h-c2jc-7f22).
  The built panel doesn't contain Vite.

## [0.12.0] - 2026-10-08

### Changed

- **Tamandua is now Pitangus**: the great kiskadee (*Pitangus sulphuratus*, the bird Colombians call bichofué), made in
  Colombia by Arodium. New logo and palette in the panel and the PDF reports, and a new tagline: "Spot it. Fix it.
  Prove it." The repository moved to `Pitangus-Dev/pitangus`.
- **Every technical name follows, with no aliases**: the package and CLI (`pitangus`, `python -m pitangus`), the
  `PITANGUS_*` variables, the images (`ghcr.io/pitangus-dev/pitangus`, `-worker`, `-opengrep`), the GitHub Action
  (`Pitangus-Dev/pitangus`), the compose project, containers, database, user and volume (`pitangus`, `pitangus-pg`),
  the `X-Pitangus-*` headers, the session cookie (everyone signs in again), the `pitangus_*` metrics, the commit
  status context (`pitangus`: update branch protection rules that required `tamandua`), the DNS record for new domain
  verifications (`_pitangus.<domain>`) and the ids of custom secret rules (`pitangus-<id>`).
- **Kept working**: Jira field mappings saved with the old variable source (migrated on start), threat models exported
  as `tamandua-threat-model`, and domains already verified with their `_tamandua` record. On pull requests reviewed
  before the upgrade, the next review writes a new comment instead of updating the old one.

### Upgrading from Tamandua 0.11

1. On 0.11, take a backup: `make backup`.
2. Check out `v0.12.0` from `https://github.com/Pitangus-Dev/pitangus` and rename the variables in `.env`:
   `sed -i.bak -e 's/TAMANDUA_/PITANGUS_/g' -e 's#tamandua-appsec/tamandua#pitangus-dev/pitangus#g' .env`.
3. `make up` starts the new `pitangus` project with an empty database.
4. `make restore FROM=backups/<date> CONFIRM=restore` brings your data back.
5. Once everything works, remove the old containers with `docker compose -p tamandua down`. The old `tamandua-pg`
   volume stays until you delete it yourself.

## [0.11.0] - 2026-10-06

First release from this repository. Tamandua is in beta: the API and stored formats may change between minor
versions, and anything that changes behaviour is called out here.

### Included

- **Find**: Opengrep with Tamandua's rules (JS/TS, Python, Java, Go, PHP, Ruby, C#), Gitleaks, Trivy and OSV-Scanner
  for dependencies, Checkov and zizmor for infrastructure as code and GitHub Actions, Trivy and Grype for images, with
  no duplicates across engines. The code under analysis is never executed.
- **Prioritize and fix**: CISA KEV and EPSS on every advisory, the version that closes all of a package's advisories,
  the fix command for each package manager, **Verify again**, and automatic remediation once a finding is gone.
- **Pull requests and CI**: only what a PR introduces counts, with a comment and a status check; the GitHub Action
  and `tamandua scan` for any other CI (exit codes `0` pass, `1` findings, `2` usage error, `3` incomplete).
- **Evidence**: technical and audit PDF reports (SOC 2, ISO/IEC 27001), SARIF, JSON and Markdown, SBOM and VEX, and
  threat modeling tied to the findings. English and Spanish.
- **Self-hosting**: `make up` on a laptop; `make setup DOMAIN=…` on a server, with HTTPS (Caddy), the engines inside
  the worker image and **no Docker socket** (opt in with `SOCKET=1`); one compose file for Docker panels; Render.
- **Supply chain**: images for amd64 and arm64 signed with cosign (keyless), with SBOM and SLSA provenance; the GitHub
  Action and `make up` run exactly the digest whose signature they checked; Python dependencies locked with hashes;
  third-party images and actions pinned by digest; no release with a fixable critical vulnerability.
- **Operations**: backups encrypted with age (master key included) or, unencrypted, without the master key; restores
  that check every archive first; health checks, Prometheus metrics and memory and process ceilings.

### Upgrading from 0.10

- On a server set up with 0.10, the worker keeps the Docker socket. `make setup DOMAIN=… SOCKET=0` and `make up`
  move it to the engines inside the worker ([deploy-vps.md](docs/deploy-vps.md#engines-and-the-docker-socket)).
