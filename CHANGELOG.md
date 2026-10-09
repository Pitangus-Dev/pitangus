# Changelog

Notable changes to Pitangus (called Tamandua up to 0.11). The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions are `major.minor` in the code (`pitangus/version.py`)
and `major.minor.patch` in the release tags. While Pitangus is in beta (0.x), the API and stored formats may change
between minor versions: anything that changes behaviour is called out below.

## [Unreleased]

### Added

- **Findings of several assets at once.** Findings has the same scope picker as Compliance: one asset (as before, with
  its runs and settings), an organization, a chosen set of repositories and images, or everything, with the images
  built from the chosen repositories. The cards add up the whole scope, a "By asset" block shows each asset's pending
  and critical findings and opens it on its own, and the table gains an Asset column. Triage (one finding or a
  selection across assets in one request, applied asset by asset with any failure named), Jira issues and the
  consolidated audit evidence work on the scope. The scope stays in the address, so a reload or a shared link opens the
  same view. New route `GET /api/findings/scope`; a very large scope lists the 10,000 most urgent findings of the tab
  and says so. `POST /api/findings/triage` also takes `selections` (`[{run_id, fingerprints}]`, one per asset, up to 500
  findings in all) instead of `run_id` and `fingerprints`, and answers each one's outcome in `results`; it fails as a
  whole only when none landed. The cards are counted by the server in every view: `summary.kpis` in an asset's state,
  a run (`GET /api/runs/{id}`) and a scope, with what was fixed (by a scan or by hand) never counted as pending.

- **Create the GitHub App from the panel** (Integrations → GitHub → Create on GitHub). GitHub's form opens with
  everything filled in (name, the four permissions, no webhook or OAuth, the return to this panel); you confirm there
  and come back with the App connected, instead of copying values and uploading the `.pem`. The App is still yours and
  its private key goes from GitHub straight to the server, encrypted; the link is single-use and lasts an hour. The
  manual guide stays, folded underneath. API: `POST /api/integrations/github/manifest` and the return at
  `/github/app-created`.

- **Add an image without scanning it** (Scanning → Images → Add image). Type its reference and, if you're an
  administrator, the repository it's built from; it shows on the list as "Not scanned yet" and is scanned when you
  choose ("Scan it now" does it right away). Adding one that is already there says so; if it isn't scanned yet, it now
  scans the reference you just typed. Its first scan lands on the same asset, keeping the link; until then it has no
  findings and stays out of the evidence scopes. At most 5,000 images wait unscanned at a time (scanned ones don't
  count). An administrator can remove an image that was never scanned. API: `POST /api/images` and `POST /api/images/remove`;
  `GET /api/images` items carry `analyzed`.

- **Connecting an installation takes one click.** Coming back from installing the App on GitHub (its Setup URL) no
  longer stops at a page that says to go back and look for it: it opens Integrations, which offers that account with
  **Connect** (only to administrators; the server still checks it belongs to the App). `/oauth/callback` no longer calls
  GitHub: it only hands the installation to the panel.

### Fixed

- **Slack messages no longer show a warning next to "Open in Pitangus".** It was a button, and Slack treats every
  button as interactive: with an incoming webhook (no interactivity URL) it marked it with a warning. It is now a plain
  link that opens the same page.

### Security

- **The images no longer carry pip.** It installs the pinned dependencies and is then removed, from the app image and
  from Checkov's environment in the worker with the engines inside: nothing runs it, and the 25.0.1 that Python 3.12
  bundles has six known vulnerabilities (pip 26 would trade them for its vendored urllib3, msgpack and setuptools).
- **Checkov's asteval goes to 1.0.10** in the worker with the engines inside. Checkov 3.3.19 (and every later release
  so far) pins 1.0.6, which it uses to evaluate the Terraform expressions of the scanned repository; 1.0.9 fixed two
  sandbox escapes (GHSA-89v8-rhwq-hf77, GHSA-9w56-46f6-3qhx). It is installed by hash over the lock, from
  `docker/checkov/overrides.txt`; Checkov's results don't change.
- **The Docker client in the image goes to 29.9.0**, built with Go 1.26.9: the 13 Go standard library vulnerabilities
  of 29.8.2 (two high: CVE-2026-78667, CVE-2026-97031) are gone. It came out on 2026-10-09, so it goes in as an
  exception to the week-old rule, checked against its SHA-256 like before.
- The Python base image moves to the current `python:3.12-slim-bookworm` digest (still Python 3.12.15). The engines stay
  where they were: they are already the newest releases at least a week old, and the Go standard library fixes their
  remaining findings need (Go 1.26.9 and 1.27.2) came out on 2026-10-08.

## [0.12.1] - 2026-10-09

### Added

- **Images page** (Scanning → Images): every analyzed image, the repository it's built from and how it was linked
  (OCI label or by hand), with a "not linked" tab for the ones that still need one. An administrator links, changes or
  removes the link there; each row opens its findings or scans the image again. Repositories show how many images are
  built from each one, and from a repository you can link another image to it.
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

### Changed

- **The panel's paths are English** (`#/findings`, `#/compliance`, `#/images`…) whatever its language, so a shared link
  reads the same for everyone. The Spanish paths of earlier versions (`#/hallazgos`, `#/resumen`…) still work and are
  rewritten, so links already sent in Jira issues, notifications or bookmarks don't break.
- **New look for every PDF report** (technical, audit evidence, consolidated, threat model): a cover with the system,
  date, revision and reference; «Confidential» on every page and «page N of M» in the footer; Source Serif 4 and IBM
  Plex (embedded, SIL OFL) instead of Helvetica; ruled tables and key figures without fills; severity as coloured text.
- **The technical report reads like one a person would write**: a short executive summary, each action with an ID
  (PIT-001…) used throughout the report, and one sheet per critical or high code finding with what happens, how to
  fix it (before and after) and how to verify it. Method, coverage, sources and the closing notice are together in
  "About this report".

### Fixed

- `make openapi` works again: `openapi-typescript` runs from `web/tools/openapi` with the TypeScript 5 its compiler API
  needs (the panel moved to TypeScript 7).

- **A Jira rule's backfill no longer skips findings whose issues were deleted in Jira.** Like a manual export, it now
  asks Jira which linked issues still exist and creates again the ones that are gone; before, a cleanup in Jira left
  those findings out of every backfill. The backfill dialog's count asks Jira too, so it no longer offers "0 issues"
  when the linked ones were deleted.

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

### Upgrading from 0.12.0

- `make update` (or `git pull` and `make up`): the published `0.12` images move to 0.12.1. No migration to run by hand.
- The panel's addresses are now English; bookmarks and links with the Spanish ones keep working.

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
