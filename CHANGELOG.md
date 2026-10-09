# Changelog

Notable changes to Pitangus (called Tamandua up to 0.11). The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions are `major.minor` in the code (`pitangus/version.py`)
and `major.minor.patch` in the release tags. While Pitangus is in beta (0.x), the API and stored formats may change
between minor versions: anything that changes behaviour is called out below.

## [Unreleased]

### Added

- **One scope picker for the evidence in Compliance.** Three steps: which assets (one, an organization, several or all),
  which framework, and the downloads for that scope, with a preview of what it covers (repositories, images, how many
  with a complete scan) before downloading anything. The separate "one asset" and "portfolio" blocks are gone.
- **An image knows which repository it is built from.** Pitangus reads its OCI labels (`org.opencontainers.image.source`
  and `.revision`, set by `docker/build-push-action` and GHCR) and links it to that repository when it is analyzed too;
  an administrator can set or change the link by hand in Compliance. The reports say "built from org/repo @ commit".
- **Portfolio evidence for the scope you choose**: every analyzed asset, the repositories of one organization, or a
  chosen set of repositories and images; with a repository come the images built from it (it can be turned off). It
  applies to the portfolio SBOM, VEX and consolidated audit evidence.
- **Audit evidence for eleven more frameworks.** European Union: NIS2 (Art. 21(2) and Implementing Regulation
  2024/2690), DORA (with RTS 2024/1774) and GDPR Art. 32. United States: NIST SSDF (SP 800-218), NIST CSF 2.0,
  NIST SP 800-53 Rev. 5 and the HIPAA Security Rule. Mexico: CNBV rules for banks (CUB) and crowdfunding institutions,
  e-money institutions (IFPE) and LFPDPPP Art. 18. Each control says what the evidence covers and what stays out
  (infrastructure scanning, external pentests, dynamic testing): it supports an audit, it doesn't certify compliance.

### Fixed

- `make openapi` works again: `openapi-typescript` runs from `web/tools/openapi` with the TypeScript 5 its compiler API
  needs (the panel moved to TypeScript 7).

### Changed

- **New look for every PDF report** (technical, audit evidence, consolidated, threat model): a cover with the system,
  date, revision and reference; «Confidential» on every page and «page N of M» in the footer; Source Serif 4 and IBM
  Plex (embedded, SIL OFL) instead of Helvetica; ruled tables and key figures without fills; severity as coloured text.
- **The technical report reads like one a person would write**: a short executive summary, each action with an ID
  (PIT-001…) used throughout the report, and one sheet per critical or high code finding with what happens, how to
  fix it (before and after) and how to verify it. Method, coverage, sources and the closing notice are together in
  "About this report".

### Fixed

- **A Jira rule's backfill no longer skips findings whose issues were deleted in Jira.** Like a manual export, it now
  asks Jira which linked issues still exist and creates again the ones that are gone; before, a cleanup in Jira left
  those findings out of every backfill. The backfill dialog's count asks Jira too, so it no longer offers "0 issues"
  when the linked ones were deleted.

### Fixed

- **Threat diagram arrows no longer run behind other components.** Each flow picks the sides and the curve that go
  around what is in between, and flows leaving the same side of a component spread along it instead of starting at one
  point; the editor, the SVG and the PDF draw them the same way. In the bundled examples, flows running over another
  component went from 108 of 156 to 12 (one flow per example still needs a route with bends). Wide curves and their
  labels now stay inside the exported drawing.

- **A threat marked mitigated or not applicable while the scans still find it** goes back to "with evidence", with a
  note saying who decided and asking to review the decision. The decision is kept and applies again once the
  evidence is gone.
- **Threat model reports for MITRE ATT&CK and attack trees** now open with their own figures (techniques by status;
  goals still reachable or cut), with the techniques or the trees in the body instead of an appendix after "0
  threats". An attack tree with no steps yet is no longer counted as cut.
- **LINDDUN is no longer mixed with STRIDE**: its "D" and "I" are counted apart, and the OWASP Threat Dragon export
  names its threats (Detecting, Identifying…) as LINDDUN instead of Denial of service or Information disclosure.
- "What to address first" no longer repeats a component already listed with evidence, and shows the high patterns
  when there are no critical ones. A flow can't take a component's ID. Smaller fixes: appendix letters in order,
  decision dates, plurals in Spanish, ATT&CK names in the report's language, linked repositories counted apart from
  pending ones, and the closing note no longer left alone on the last page.

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
