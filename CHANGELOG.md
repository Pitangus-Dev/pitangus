# Changelog

Notable changes to Pitangus (called Tamandua up to 0.11). The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions are `major.minor` in the code (`pitangus/version.py`)
and `major.minor.patch` in the release tags. While Pitangus is in beta (0.x), the API and stored formats may change
between minor versions: anything that changes behaviour is called out below.

## [Unreleased]

### Security

- **The SSRF checks judge IPv6 addresses that carry an IPv4 by that IPv4.** Python's `ipaddress` calls NAT64 addresses
  (`64:ff9b::/96`, RFC 6052) global whatever they embed, so on an IPv6-only network with DNS64/NAT64 a domain, registry
  or webhook whose name resolved to `64:ff9b::a00:1` passed the check and reached 10.0.0.1. One shared check
  (`pitangus/shared/addresses.py`) now backs the domain probe and verification, the registry check, the webhook URLs and
  the egress detection: NAT64 well-known and IPv4-mapped (`::ffff:0:0/96`) addresses are public only when their IPv4
  is; the NAT64 local-use prefix (`64:ff9b:1::/48`, RFC 8215, where the operator decides where the IPv4 sits) and the
  deprecated IPv4-compatible form (`::/96`, which `ipaddress` also called global) never are; 6to4 (`2002::/16`) and
  Teredo (`2001::/32`) stay refused as before, and their embedded IPv4 is checked too. A NAT64 prefix of the
  operator's own (network-specific, any global /96) can't be told apart from a normal address: on such a network, keep
  the server's own egress filtering.
- **Pillow 13.0.0** (was 12.3.0; it comes with ReportLab, which draws the PDF reports). Fixes GHSA-8g5g-8vmr-9782
  (CVE-2026-112403, critical: heap overflow decoding a lossless JPEG), GHSA-58r4-6rv3-gfh8, GHSA-65qm-jvmh-6pqg,
  GHSA-q45j-58j2-45rg, GHSA-pchr-8j38-3x4p, GHSA-p4wg-p73j-c528, GHSA-c6hw-5grf-ff96 (high), GHSA-vx6w-vv9f-6gvg and
  GHSA-462x-pgg6-55fp (medium). Pitangus only hands Pillow its own logo (a PNG in the package), never an image or PDF
  from a user or a repository, so none of these was reachable; the image no longer carries them. Pillow 13's removed
  APIs aren't used by Pitangus or by ReportLab 5.0.1, and the reports render the same.
- **certifi 2026.10.19** (was 2026.7.22): GHSA-6q48-6c7w-9gw2 (critical), the emSign root whose intermediate CAs had
  their keys compromised. certifi is only in the development lock (the tests' HTTP client) and in Checkov's environment
  in the `pitangus-worker` image, where Checkov runs without network; the app image doesn't carry it.
- **aiohttp 3.14.4** (was 3.14.3) in Checkov's environment in the `pitangus-worker` image: GHSA-9xw5-w5jj-pvcg,
  GHSA-5wr8-gcqf-gqf3, GHSA-2g87-pp6c-29x5 (high), GHSA-f9xw-jh8m-3mwq, GHSA-6cjc-53gc-5rqm, GHSA-pqxq-w44r-73xw
  (medium), GHSA-gx76-c99x-2c96 and GHSA-494j-54xm-rwp3 (low). Most are in aiohttp's server, which Checkov doesn't run,
  and Checkov makes no connections in Pitangus. Checkov 3.3.19 allows it (`aiohttp<3.15`), so no override is needed.
- **Image scan: a history step can no longer hang the worker.** Rebuilding the Dockerfile from an image's history
  read the build arguments of a `RUN |N KEY=value …` step with a pattern that backtracked exponentially when the values
  carried `=` (base64 padding, for instance) and no `/bin/sh -c` followed: about forty such arguments kept a worker busy
  for good. Argument names can't contain `=` any more, so it is read in linear time with the same result (CodeQL
  py/redos).
- **Hardening found by CodeQL's first analysis** (none was exploitable): the domain proofs and the reachability check
  require TLS 1.2 or later explicitly, instead of relying on the interpreter's default; the server version in a web
  finding's evidence and the `requirements*.txt` name check no longer take quadratic time on long input (both inputs
  were already short).
- **CodeQL leaves the tests out** (`tests/` and the panel's `*.test.ts(x)`), as it already did with `fixtures/` and
  `rules/tests/`: they plant made-up secrets and hostile input on purpose. The demo sample's `osv-scanner.toml`
  declares two newer lodash 4.17.20 advisories (GHSA-xxjr-mmjv-4gpg, GHSA-r5fr-rjxr-66jc), which the demo still shows.

## [0.15.1] - 2026-10-17

### Upgrade notes

- **Nothing to do.** No database or data migrations and no new required settings; `make update` is all it takes.
  `PITANGUS_PUBLIC_DEMO` (with `PITANGUS_PUBLIC_DEMO_USER` and `PITANGUS_PUBLIC_DEMO_PASSWORD`) is new and optional, only
  for a public demo with made-up data: leave it unset on a normal installation.

### Added

- **A read-only public demo** ([deploy/demo](deploy/demo/README.md)). `PITANGUS_PUBLIC_DEMO=1` turns an installation
  into a demo anyone can open with published credentials, on the made-up Lapis Labs organization that `pitangus demo
  --full --recorded-only` builds without engines or network. The server, not the panel, enforces it: it answers 403
  (`public_demo`) to everything but reading, signing in and out and the evidence PDFs; only the demo account can sign in;
  nothing runs in the background and no connection leaves the API process; and it refuses to start with integration
  credentials set or with EUVD, the CVE sync, secret validation or the embedded worker on. The panel shows a read-only
  notice and the sign-in page shows the demo credentials. `deploy/demo/` brings it up on any VPS behind a tunnel.
- **A "Supply chain" page** ([docs/supply-chain.md](docs/supply-chain.md)): what is pinned by digest or commit, how
  release images are built and signed, and the commands to verify one before installing it.
- **OpenSSF Scorecard** (`.github/workflows/scorecard.yml`) on every push to `main`, weekly and when branch
  protection changes, with its badge in the README. It reads the repository and changes nothing.
- **Signed files on every GitHub release.** After the images are built, signed and verified, `release.yml` attaches to
  the release of the tag the SPDX SBOM of each image and platform, their SLSA provenance (`.intoto.jsonl`) and a manifest
  of the image digests signed with cosign (keyless, the same identity as the images). The job waits up to 15 minutes for
  the release, which a maintainer still creates by hand, and never creates it. How to verify them is in
  [Supply chain](docs/supply-chain.md#release-assets).
- **CodeQL** (`.github/workflows/codeql.yml`) analyzes the Python, the panel's and docs site's TypeScript and the
  workflows on every pull request, on pushes to `main` and weekly, with results in code scanning: a second opinion next
  to "Pitangus on itself". The samples that are vulnerable on purpose and the panel's build output are left out.
- **Property-based tests in the panel** (fast-check, a development dependency): the Jira routing patterns are checked
  against a reference reading of `fnmatchcase`, a scope read from any link against the API, and a domain's next
  scheduled scan against every time zone and clock change, over thousands of generated cases each.
- **The advisories that don't apply to this repository are declared** in an `osv-scanner.toml` next to each manifest,
  with the reason for each: the demo's vulnerable sample (`fixtures/scanner-samples`, never installed or run) and
  `ecdsa` in Checkov's requirements (its timing advisory affects signing; Checkov only verifies signatures, and only
  for signed external checks, which Pitangus never loads). `make demo` copies the sample without that file, so the demo still
  reports those advisories as open findings.

### Changed

- **The GitHub Action is named "Pitangus Security Scan"**, by Arodium, ready for the GitHub Marketplace (a GitHub
  account already uses the name "Pitangus"). Workflows keep `uses: Pitangus-Dev/pitangus@<version>`; nothing else
  changes.
- **Questions and ideas go to GitHub Discussions**: the issue chooser links to Q&A and Ideas and no longer opens blank
  issues.
- **The security policy** ([`.github/SECURITY.md`](.github/SECURITY.md)) is complete: private reporting link, what to
  include, response targets, coordinated disclosure, supported versions (the latest minor line) and scope.
- **Every new feature and fix needs tests**, now written in CONTRIBUTING and the pull request template, and the
  README shows the OpenSSF Best Practices badge (passing).

### Fixed

- **The Jira routing preview now matches what the server decides.** A pattern with `]` first in a bracket (`[]a]`,
  `[!]a]`), a reversed range next to a valid one (`[a-cz-a]`) or a character outside the BMP (an emoji under `?`) was
  read differently by the panel than by Python's `fnmatchcase` on the server, so the panel could show a different rule
  for an asset than the one that applied (found by the new property-based tests). A pattern full of stars
  (`*a*a*a…*b`) could also freeze the page; it now answers at once, as the server does.
- **A link to Findings with a long organization name no longer breaks the view.** The name was cut at 100 UTF-16 units,
  which could split an emoji in two and make the request to the API throw. It is now cut at 100 characters. Found by
  the new property-based tests.
- **A malformed advisory link no longer breaks a finding's detail.** References that aren't valid http(s) URLs are
  shown as text instead of links, and a source URL that isn't http(s) isn't linked.

## [0.15.0] - 2026-10-16

### Upgrade notes

- **No database migrations.** This release has no Alembic or data migrations: the engine switches are kept as settings
  documents in the existing database, created when an administrator first changes one. `make update` is all it takes.
- **Every engine can now be turned on or off from the panel.** Defaults don't change: every engine is on but Checkov,
  Grype and the full web scan. A server that sets `PITANGUS_CHECKOV_ENABLED`, `PITANGUS_GRYPE_ENABLED` or
  `PITANGUS_DAST_ENABLED` today keeps them as they are. The new `PITANGUS_<ENGINE>_ENABLED` variables
  (`OPENGREP`, `TRIVY`, `OSV_SCANNER`, `BETTERLEAKS`, `ZIZMOR`, `HTTPX`, `TESTSSL`, `NUCLEI`, `KATANA`) are optional: set
  one, on both the API and the worker, and it wins over the panel and locks that switch; leave it unset and an
  administrator decides in **Settings → Analysis engines**. Turning an engine off fixes nothing it found.
- **An analysis run by the server no longer downloads a missing engine image.** The worker prepares the images of every
  engine that is on, by digest, in a lane of its own (every 5 minutes, and at once when an engine is turned on). After
  an upgrade that changes an engine's digest, the first analyses before its image is ready show that engine as not run
  (being prepared), and nothing it found before is marked fixed; the next scan runs it. `make engines` still pulls the
  images of the engines the environment and `.env` turn on, and one-shot scans (`pitangus scan`, the GitHub Action, the
  pre-commit hook) still pull a missing image as they start.
- **The Action and the pre-commit hook now point at the 0.15 worker image**
  (`ghcr.io/pitangus-dev/pitangus-worker:0.15`). Until the release publishes it, the hook runs the signed digest of the
  last release's image; `make pin-hook` points it at the new one.

### Added

- **Analysis engines from the panel.** Administrators turn each engine on or off in **Settings → Analysis engines**,
  grouped by what it checks (code and dependencies, secrets, infrastructure and CI, images, web): Opengrep, Trivy,
  OSV-Scanner, Betterleaks, Checkov, zizmor, Grype, httpx, testssl.sh, nuclei, katana and the full web scan. Defaults
  don't change (all on but Checkov, Grype and the full web scan). Every change is kept with who made it and when, and
  logged. Turning a core engine off asks first and says what goes unchecked; its step in every scan says **not run
  (disabled)** with where to turn it back on, and what it found stays open, never marked fixed. A kind of check left
  with no engine (every secrets engine off, say) is warned about in the panel and said in each scan.
- **Engine images are prepared on their own.** Each engine says whether its images are on the server. Turning one on
  queues its images at once, and every 5 minutes the worker pulls, by digest, those of every engine that is on and
  missing them (after an upgrade that changed a digest, say), in a lane of its own so queued analyses keep running;
  **Prepare engine** retries by hand. An analysis the server runs no longer downloads a missing image mid-run: the
  engine is declared not run (being prepared, it runs in the next scan) and fixes nothing it found before. One-shot
  scans (`pitangus scan`, the GitHub Action, the pre-commit hook) still pull a missing image by digest as they start.

### Changed

- **`PITANGUS_<ENGINE>_ENABLED` pins a switch.** `PITANGUS_CHECKOV_ENABLED`, `PITANGUS_GRYPE_ENABLED` and
  `PITANGUS_DAST_ENABLED`, and the new `PITANGUS_OPENGREP_ENABLED`, `PITANGUS_TRIVY_ENABLED`,
  `PITANGUS_OSV_SCANNER_ENABLED`, `PITANGUS_BETTERLEAKS_ENABLED`, `PITANGUS_ZIZMOR_ENABLED`,
  `PITANGUS_HTTPX_ENABLED`, `PITANGUS_TESTSSL_ENABLED`, `PITANGUS_NUCLEI_ENABLED` and `PITANGUS_KATANA_ENABLED`, set
  in the server's environment, win over the panel and show its switch locked, naming the variable; unset, the panel
  decides. A server that sets `PITANGUS_CHECKOV_ENABLED=1` today keeps Checkov on, as before. `make engines` still
  reads only the environment and `.env`; the worker prepares what the panel turns on.

## [0.14.3] - 2026-10-15

### Added

- **The full MITRE ATT&CK catalog in threat models.** The hand-made technique list is replaced by MITRE ATT&CK
  Enterprise v19.2, pinned by SHA-256: 697 current techniques (222 techniques and 475 sub-techniques) and their
  platforms. **Map a technique** opens the whole catalog, filtered by tactic and searchable by ID or by name in English
  or Spanish, with the total and its source in view.
- **Suggested techniques come from the component's platform, and say why.** One documented table
  (`SUGGESTION_RULES`, in [Threat modeling](docs/threat-modeling.md)) ties each component type to MITRE platforms and
  tactics; a component exposed to the internet adds Initial Access and container technologies add the Containers
  platform. The picker groups them under **Suggested for <component>** with the platforms and tactics that justify them,
  and the suggestions panel lists one row per technique with the components it applies to and **Add to all N**. Actors
  and custom types get none, and the panel says so.
- **Spanish names under MITRE's.** Every technique and tactic shows MITRE's official English name with its Spanish
  translation below, in the panel and in the reports.
- **Movable flow labels in threat-model diagrams.** Drag a flow's label with the pointer or move it with the keyboard
  (arrows, Shift for big steps, Escape to cancel); double-click, **Reset label** or **Tidy up** put it back where it
  goes by itself. The offset (`label_offset: {x, y}`, ±1000 per axis) is kept relative to the middle of the flow's
  curve, so the label follows its line when you move the nodes, and a thin line joins it to its flow when it is far.
  The panel, the SVG, the PDF and the Markdown place it the same way, moved labels first and automatic ones around them.
  It travels in the portable JSON; Threat Dragon and pytm ignore it, and an invalid or out-of-range value is dropped
  with a warning.
- **The threat-model importer keeps more.** A tree step can have properties added, and numbers and yes/no values keep
  their type.

### Changed

- **Select menus size to their content**, so the **+ Component** menu is no longer cut off.
- **A technique's note grows with its text** instead of scrolling in a fixed box.
- A flow label's corners are rounded to 4 px, as the identity manual asks.

### Fixed

- **Unused dependencies: a lockfile is not a declaration.** Pull request review reported transitive packages of
  generated `requirements.txt` files as unused (79 in this repository, now 0). A `requirements*.txt` counts as a
  lockfile when it carries `# via`, when every entry has a hash or when its header says pip-compile, uv, pdm or poetry
  made it; with a `.in` sibling the declaration is read from there, and in a lockfile only the entries marked `# via -r
  <file>` count as declared. A direct dependency that is really unused is still reported, on its line.
- **npm, pnpm, yarn, bun, Poetry, uv, pdm and Pipenv lockfiles no longer count as proof a package is used.** In pnpm
  projects every dependency used to look used.
- **A dialog's fieldset never overflows** (the link-images dialog).

## [0.14.2] - 2026-10-15

### Changed

- **Every count on Findings agrees with the header.** The status filter says how many findings each status holds
  (**Fixed · 14**), the header counts the unverified findings apart (**2 unverified**), and a view of several assets
  counts them too: its **Open** tab listed them without counting them. A run you pick still shows what that run saw.
- **Excluded paths, explained, and limited to one rule if you want.** Repository settings say in plain words what
  each setting is for, and that excluded findings stay in view under **Excluded**. The dialog lists common examples
  (`tests/fixtures/**`, `**/testdata`…) that you add with one click, and says what saving moves with the current
  findings. A known false positive in one place is a path plus a rule: `tests/** generic-api-key` excludes only that
  rule's findings under `tests`.
- **A Jira rule says what it will do before you save it.** Every enabled automatic rule is checked first, with or
  without backfill, and the form reads like a sentence: "This rule will create about 12 issues now in SEC · Bug, for open
  findings High or above in org/api; future ones as they appear", the counts behind it and how its issues will read in
  Jira. Without backfill it says nothing is created now and how many open findings stay without an issue; a manual rule
  says where the issues created from Findings go.
- **The field mapping explains its choices.** The three ways to fill a field are named for what they do (a Pitangus
  value, the same value always, your text with Pitangus values), each with an example; a chosen Pitangus value shows
  what it holds (`GET /api/integrations/jira/variables` returns an `example` per variable) and a template suggests one.

### Fixed

- **A transitive dependency's fix no longer starts with a command that changes nothing.** Where the lockfile records
  the range each package accepts (`poetry.lock`, `package-lock.json`, `yarn.lock`, `Gemfile.lock`), the scan reads it
  next to the graph Trivy resolves. When the package that brings it in doesn't accept the fixed version (FastAPI 0.110.1
  only accepts `starlette>=0.37.2,<0.38.0`), the guide, the Jira issue and the reports say so and put the direct
  dependency first (`poetry add fastapi@latest`, then `poetry update starlette`, then `poetry show starlette`), with
  the range the manifest declares for it; npm's override becomes the last resort. When the range accepts it, updating
  the package is enough (`npm update qs` for npm). When no engine resolved who brings it in, the guide says it doesn't
  know instead of assuming.
- **The README and the docs claim only what the fix guide can know:** it's built from the lockfiles and the
  advisories, not from your code.
- **Jira descriptions no longer glue words together.** Text next to a bold word, a link or a version lost its space in
  Jira ("Repository:org/api", "Severity:High· Due date:…"); the spaces between parts are kept.

## [0.14.1] - 2026-10-15

### Upgrade notes

- **Pitangus no longer stores your code.** It keeps a finding's location (path, lines, a secret value's columns, the
  scanned commit), its rule, structural metadata and hashes; the code is read from the repository when someone opens
  the finding, and never stored, cached or logged. The data migration `drop_stored_code` removes the snippets earlier
  versions stored (runs, the registry, stored SARIF and reports, pending outbox entries), after pinning each finding's
  identity from them: nothing looks new or fixed, and no status changes.
- **A finding's code needs the repository to be reachable.** It is read with the connection Pitangus already has (the
  GitHub App or the token) at the commit the scan read. A repository Pitangus can no longer read, a run that didn't
  record its commit (older imports without `--commit`) or a local scan show the location and say why there is no code.
- **The AI prompt is built where you are.** `GET /api/findings/prompt` no longer carries code: it returns the prompt's
  parts (`before`, `heading`, `language`, `after`) and the panel adds the lines you opened. `pitangus scan --format
  prompt` reads the scanned folder at that moment (not with `--commit` or `--staged`).
- **One rule for what a repository says to the engines: honoured, never silent.** Comments and files in the scanned
  repository that make an engine report less were honoured without a word by zizmor (`# zizmor: ignore[…]`,
  `.github/zizmor.yml`), Trivy (`trivy:ignore`), Checkov (`checkov:skip=`, `checkov.io/skip` annotations) and
  OSV-Scanner (`osv-scanner.toml`). Now every result one of them suppresses is listed under **Excluded** with its rule,
  file and line and what suppressed it, and never taken as fixed. A committed `.trivyignore` / `.trivyignore.yaml` and
  `.checkov.yaml` are now read (before, they never reached the engines) and declared the same way. A repository with such
  suppressions may show new excluded results, and its earlier open findings they suppress move to excluded.
- **Web scan evidence is still stored.** What a live site answered (a web finding's evidence and attack) isn't
  repository code and can't be read again later, so it stays, rendered as structure and common words like engine text.
- `PITANGUS_SECRETS_IGNORE_INLINE_ALLOW` is now `PITANGUS_IGNORE_REPO_SUPPRESSIONS` and covers every engine (with it on,
  a `nosemgrep` comment silences nothing either). The old name still works.

### Added

- **Code on demand.** `GET /api/findings/code?run_id=…&fingerprint=…` returns the lines around a finding for anyone who
  can read it, with every place a secret engine reported in that file masked (a value with known columns replaced, any
  other secret's line withheld, a private key's whole block); a secret or a hard-coded credential shows only where it
  is. The finding's detail in the panel loads it lazily, with **Open on GitHub** to the file at the scanned commit.
- The Markdown report links each code finding's location to the file at the scanned commit.

### Changed

- An Opengrep rule without its own fix text no longer uses its message (which quotes the matched code): it gets a
  sentence naming the rule. A Trivy configuration check is described by its description, never by its message.
- zizmor findings no longer store their route of keys; the SARIF export and imported SARIF findings carry no snippet.
- The text renderer (`shared/render.py`) now only renders what tools write (messages, errors, a web scanner's evidence)
  and URLs; there is no code to render.

### Security

- **Code on demand masks what the engines located, where they located it.** Lines end at `\n` alone and a secret's
  columns apply to the bytes as the engines read them (a form feed, a lone `\r`, U+2028 or invalid UTF-8 before a
  secret no longer moves its mask); display text is made only after masking. A key block with no end within 200 lines
  is withheld from its start on, and lines a `gitleaks:allow` comment allowed are masked too.
- **Code is read only where Pitangus scanned.** An imported (SARIF) finding shows its location and the provider's link,
  never code: its path, line and commit came with the import. A symbolic link is never read (on the server or by
  `--format prompt`), and a file whose secrets are known only from another commit shows no code (their lines may have
  moved).
- **Engine control files from the repository can't hide results** (O9 of the 0.14 audit). zizmor runs once more with
  `--no-config --no-ignores`, Checkov and Trivy once more on a copy with their comments made inert and OSV-Scanner once
  more with an empty configuration of Pitangus' own, only when the repository has such suppressions; what only that run
  reports is what they hid. Checkov never loads the repository's `.checkov.yaml` (Pitangus applies its `skip-check`,
  `check` and plain-path `skip-path` entries, never a regular expression from the repository); Trivy reads the
  repository's ignore file only through `--ignorefile`, with `--show-suppressed`. If that second run fails, the step is
  partial and the scan fixes nothing. A `.gitleaksignore` entry now applies to the code's files too, not only to the
  files only the secret scanners read.
- **The pre-commit hook runs the worker image by digest and checks its signature.** `hooks/pitangus-docker` no longer
  runs the `pitangus-worker:0.14` tag, which can move: it runs the digest of the published release and, when cosign is
  installed, first checks it was signed by Pitangus's release workflow (the GitHub Action's identity), refusing to run
  it otherwise. `make pin-hook` checks the signature and writes the digest after each release.
- **Locating secrets has one CPU budget.** All the work of reading where a secret's value is (each line read, each
  candidate checked, each value read out) counts against one budget per file and per engine report. A long line where
  the text before a redacted value (or the text Trivy shows around a masked one) repeats everywhere used to make every
  occurrence a candidate outside any budget. Past the budget, the secrets left there are reported unlinkable (no
  identity of their own, never a guessed one) and the run's limitations say how many.

## [0.14.0] - 2026-10-15

### Upgrade notes

- **Proof before fixing and one identity per problem are on by default.** `PITANGUS_COVERAGE_MODE` defaults to `on`
  and `PITANGUS_IDENTITY_MODE` to `v2`. On the first scan after upgrading the identity change opens and fixes nothing:
  findings move to their families with their triage (copies that disagree go back to review, with a note), and a scan
  that would fix 30% of an asset's open findings and at least 10 holds those fixes until a second covered scan
  confirms each one. To keep 0.13's behaviour while you check, set both to `shadow` and run `pitangus identity-gate`.
  GitHub code scanning sees SARIF alerts once as new: their `partialFingerprints` now carry the identity.
- **Changing the configuration never fixes.** Every scan records the engines and rules it ran with; a finding whose rule
  was turned off, changed or whose engine is off stays open as **Unverified (configuration)**, in every coverage mode.
  The data migration `registry_rule_baseline` stamps stored findings with the rules of 0.13.1, so a finding whose rule
  changed in 0.14 and that disappears on the first 0.14 scan shows that way instead of fixed: mark it fixed by hand if
  it's really gone. The same holds for a secret the new secret filter sets aside.
- **Engines change, and nothing is fixed by the change.** Secrets go from Gitleaks to Betterleaks (same configuration
  format; findings keep their identity, and what Gitleaks found is Betterleaks' to prove gone). Checkov and Grype are now
  optional and off: re-enable them with `PITANGUS_CHECKOV_ENABLED=1` and `PITANGUS_GRYPE_ENABLED=1` if you rely on them.
  The full web scan stays behind `PITANGUS_DAST_ENABLED` and is experimental; the exposure check needs nothing.
- **An engine that is off, or didn't run, never counts as a fix.** Its step says "not run (disabled)", the scan isn't
  shown as clean, and every finding it reported stays open (unverified once a scan can't check it) until an engine
  that looks again proves it gone.
- **Expect some new secret findings the first time.** Betterleaks has 463 built-in rules against Gitleaks' 222, and
  `generic-password` is on by default behind a filter (an `enabled_rules` entry for it is accepted and does nothing);
  `generic-credential-uri` stays opt-in. The secret scanners also read what their own skip lists used to leave out
  without a word: committed `node_modules/` and `vendor/` folders, lockfiles, minified files, hidden folders, tests,
  examples and Markdown, so secrets there show up now (a file an engine still passes over is listed as not analyzed by
  that engine). Matches allowed by a `gitleaks:allow` comment are listed under **Excluded** with their file and line.
  The secret pass takes longer on a repository with committed dependency folders (about 35 seconds more for a 600 MB
  `node_modules/`). Some secrets reported before are now set aside as not secrets (Supabase anon keys, placeholders,
  unsigned JWTs) and secrets in tests, docs or examples drop from **Act now** to **Attend**.
- **0.13's secrets are adopted once.** 0.13 stored secrets without their value's identity: each moves to it, with its
  triage and Jira issue, on the first scan that reads the value, once; from then on two values are never one finding.
  A value changed between the last 0.13 scan and the first 0.14 one takes the old entry's triage: review the secrets
  you had accepted or marked as false positives. If you rotate the master key later, set
  `PITANGUS_PREVIOUS_MASTER_KEY` to the old one for the next scans.
- **Stored code shows as its structure and common words, never its values.** The data migrations
  `mask_stored_secrets`, `mask_stored_credentials`, `render_stored_texts`, `render_stored_texts_lexicon` and
  `web_location_keys` render what is already stored (runs, with their steps, progress and limitations; the registry;
  pending notifications) and render again each affected run's report and SARIF. Stored snippets keep punctuation and common words only
  (`cur.execute("SELECT k FROM t WHERE v = '***'" + q)`; an identifier that isn't made of common words becomes `***`
  too), zizmor findings keep only their route in the workflow, SAST reasons no longer quote the code, an imported
  SARIF's rule titles and descriptions are rendered like its messages, and hard-coded credential findings (CWE-798,
  259, 321, 522) and secrets no longer show a code fragment. A value survives only if it is made entirely of common
  words and numbers of up to three digits (`admin123`); no other does. File paths and the pages a web scan visited are
  structure and are kept. Identities are unchanged.
- **More dependency findings stay "not checked".** A dependency finding now lives in the project folder of each file it
  was seen in, whatever the package manager (no list of lockfile names decides it): an engine examined a folder only if
  it listed a package from a file in it, and proves a finding gone only if it listed packages from the very file the
  finding came from. So deleting, emptying or replacing any lockfile (Conan's, sbt's, `renv.lock`, a `requirements.txt`
  compiled from `requirements.in`, a `pnpm-lock.yaml` at a workspace root…) never fixes its advisories while its folder
  is still in the repository; deleting the whole folder, or upgrading the package, does. A manifest whose packages didn't
  all resolve to a version (a parent POM that didn't resolve, an unpinned `requirements.txt` line) is unexamined too.
  Taking a lockfile out of a folder that stays (switching package manager there, moving the project out of the root)
  leaves what was found in it open until you mark it fixed by hand once checked.
- **Every engine that saw a finding must look again.** A finding two engines reported (Betterleaks and Trivy, Trivy and
  OSV-Scanner, Trivy and Checkov), or that an engine saw in an earlier scan, is fixed only when each of them examined
  its file in this scan. Before, the engine that owned it was enough.
- **What the commit holds and the archive doesn't is listed as not analyzed.** GitHub and GitLab archives leave out what
  `.gitattributes` marks `export-ignore`, submodules and LFS objects. Each scan now checks the snapshot against the
  commit's tree (one more API request for the commit and one or a few for its tree) and lists every entry it doesn't
  hold as committed, with the reason; so does a name with a `\` and a symbolic link. Repositories that export-ignore
  their tests or docs see those folders as not analyzed. A list longer than 5,000 entries is declared by folder.
- **Files in UTF-16 or UTF-32 are read as UTF-8**, so secrets (and code, and lockfiles) in them are found; any other
  file whose bytes aren't UTF-8 text (an EBCDIC code page, a Latin-1 file with accents, a binary) is listed as not
  analyzed by the secret scanners (`encoding`) even when their log names it, so a secret seen there is never fixed by a
  re-encoding.
- **Folders that were skipped are now scanned.** Everything committed goes through the secret scanners whatever folder
  it's in (`data/`, `out/`, nested `build/`, `vendor/`…), so new secrets and SAST findings may appear there. Dependency
  folders and build output are left out of SAST and the other engines and listed as not analyzed with the reason.
- **`appsec.js.dom-xss-sink` is off by default** (3 of 18 matches were XSS on the measured corpus): its open findings
  show as not checked (rule off); turn it on with `PITANGUS_SAST_OPT_IN_RULES`.
- **Web findings on paths that still answer 200** (a single-page app's shell, a catch-all page) stay open and unverified
  until the path answers 404 or 410: only those prove a path gone.
- **More findings and a few new exclusions on the first scan.** The policy reader catches Firebase rules it missed
  (no `;`, any signed-in user on a recursive wildcard, Realtime Database files with comments) and Supabase tables
  another project's RLS used to cover; a rules file it can't parse is now not analyzed. Packages flagged as malware
  without CWE-506 or a `MAL-` id become **Malicious · Act now**, and several advisories on one malicious version are one
  finding. SAST findings in third-party code copied into the repository move to **Excluded (third-party code)**.
- **Web scans on rate-limited sites end incomplete** when a host refuses enough of the scan (any 429 on 5% of its
  answers): allow the scanner's addresses in the WAF or CDN.
- **The pre-commit hook compares with what the remote already has** (`PRE_COMMIT_FROM_REF`) and scans the pushed commit,
  not the folder; set `PITANGUS_BASE=origin/main` to keep the old comparison. `make engines` no longer pulls Grype or
  Checkov unless they're on, and always pulls the exposure check's tools.
- **Pull request reviews and `scan --base` may report fewer findings:** code that only moved, was reformatted or
  commented is no longer new.
- Migrations: Alembic `0015_domain_session_check` and `0016_registry_control` (applied at start-up); data migrations
  `registry_identities`, `registry_rule_baseline`, `mask_stored_secrets`, `mask_stored_credentials`,
  `secret_value_identities`, `registry_coverage_units`, `dependency_project_units`, `render_stored_texts`,
  `render_stored_texts_lexicon` and `web_location_keys`. Take a backup first, as for any upgrade (`make update` does).
- **The data migrations rewrite stored data and can't be undone.** `mask_stored_secrets`, `mask_stored_credentials`,
  `render_stored_texts`, `render_stored_texts_lexicon` and `web_location_keys` replace what runs, the registry and
  reports hold, with no copy of the original. Run `make backup` before upgrading if you don't upgrade with
  `make update`: it's the only way back to 0.13.
- **The exposure check runs with `PITANGUS_DAST_ENABLED` off.** Only an admin can launch it, only on a domain whose
  ownership was verified, anonymously and only against the address it resolved to when checked (pinned), but it does
  probe ports 80 and 443 actively (httpx, testssl, nuclei). The full web scan stays behind the flag.
- **A committed `.gitleaksignore` or `.betterleaksignore` is honoured, and never silent.** Betterleaks no longer loads
  it on its own (it did so from the top of the folder it scans, whatever its flags said, which let a commit hide a secret
  with a predictable fingerprint and have it taken as fixed). Pitangus reads the one at the repository root and honours
  its entries (`path:rule:line`, as Betterleaks names them, `/src/` or not) for the files only the secret scanners read:
  each match it allows is listed under **Excluded** with its file and line, like a `gitleaks:allow` comment, and never
  counts as a fix. `PITANGUS_SECRETS_IGNORE_INLINE_ALLOW=1` makes them allow nothing, as it does for the comments.

### Added

- **Exposure check** for verified domains, always available: each host's root and known paths (exposed files, panels,
  TLS, headers) with httpx, testssl.sh and nuclei, no crawl. Coverage by HTTP status: a 404 or 410 on a path an earlier finding
  was on proves it gone; a WAF that refuses almost everything leaves it incomplete.
- **One screen to start as a developer** ([docs/quickstart-developer.md](docs/quickstart-developer.md)): one `docker run`,
  a pre-commit hook (`id: pitangus`, at pre-push) and the Action. `scan` no longer prints internal log lines unless
  `PITANGUS_LOG_LEVEL` asks for them. The engines' advisory databases outlive a run: in the `pitangus-cache` Docker
  volume for the one-liner and the hook, and in `actions/cache` for the day in the Action (input `cache`). A second scan
  doesn't download them again (on a small repository, about half the time).
- **Fix it with your own AI.** Each finding as a prompt for Claude, Cursor or Copilot (the rule, where, the matched code,
  the fix): **Copy prompt for your AI** in the panel, `pitangus scan --format prompt` in the terminal. Never a secret's
  value nor code beyond the fragment; Pitangus calls no AI.
- **Rules for what AI-written code gets wrong.** A Supabase `service_role` key in the code or in browser code, secrets,
  API keys and tokens in public-prefixed variables (`NEXT_PUBLIC_`, `VITE_OPENAI_API_KEY`…; keys meant for the browser
  such as Supabase anon or Firebase web config stay out), CORS open to any origin with credentials, routes without the
  authentication their siblings have (a global `express.json()`, `helmet()` or `cors()` no longer counts as
  authentication), JWTs decoded without verification; and a policy reader of our own, with its own coverage: Firebase
  rules read the way Firebase reads them (no `;`, helpers such as `isSignedIn()`, any signed-in user on a recursive
  wildcard, Realtime Database files with comments and test mode) and Supabase row level security per project folder,
  schema and table, with the exposed schemas of `config.toml`; a rules file it can't parse is not analyzed.
- **GitLab sast-rules, optional and off** (`PITANGUS_THIRD_PARTY_RULES`): 259 MIT and Apache-2.0 rules, provenance
  checked file by file, pinned by checksum, kept apart from Pitangus' rules with their LICENSE and NOTICE. Measured on an
  18-repository corpus, none reached 85% precision with at least 3 hits, so they stay off; turned on, a GitLab match on
  the same line and weakness as a Pitangus rule folds into the Pitangus finding (`related_rules`).
- **One identity per problem, on by default.** `PITANGUS_IDENTITY_MODE` (default `v2`; `shadow` and `v1` remain): every
  finding gets a canonical identity from its content (code without comments or formatting, a resource's address, a
  dependency's advisory, purl and normalized version, a secret's HMAC with a key derived from the master key, a web
  rule's path template, evidence and kind of scan), never from its line or the order an engine lists it. In `v2`, identical problems
  are one family with a count: a new copy reopens a triaged finding, one fewer is a partial fix, and a copy where the scan
  didn't look stays counted. `pitangus identity-gate` compares the last two full scans of each repository both ways;
  `identity-gate --scan PATH` scans a folder twice with this version and fails on anything opened or fixed (in CI).
- **Proof before fixing, on by default.** `PITANGUS_COVERAGE_MODE` (default `on`; `shadow` and `off` remain): every
  engine's run goes through one contract (exit code, the JSON it always writes, the mark it writes when it ran) and
  declares which files or pages it examined and which not, and why; a finding is fixed only when the engine that owns
  it proved it looked where it was. An open finding a scan couldn't check is **Unverified since** that scan (outside
  deadlines and indicators, warned about after `PITANGUS_UNSEEN_WARN_SCANS` scans), and a scan that would fix too much
  at once holds its fixes until the next complete scan confirms them (`PITANGUS_FIX_HOLD_PERCENT`/`_MINIMUM`; **Mark
  as fixed** for administrators, `POST /api/assets/fix-hold`). In shadow mode each asset records what the contract would have
  changed. `GET /api/findings/health` counts findings reopened soon, fix spikes, duplicates across engines, unverified
  findings and blind engines. Migration `0016_registry_control`.
- **A secret is its value.** A secret's identity is the keyed HMAC of its value, whatever key holds it, in whichever
  format (ENV, YAML, JSON, TOML, code), quoted or not, and whichever engine or rule found it: Betterleaks'
  `generic-api-key` and Trivy's provider rule on the same value are one finding, and so is a secret imported from SARIF
  (Gitleaks, Betterleaks, Trivy, or a CWE-798/259/321/522 result), which is no longer keyed by an unkeyed hash of its
  snippet. Entries stored under an earlier formula move with their triage and Jira issues on the first scan or import
  that reads the value: nothing opens and nothing is fixed. Two values are never one secret: only names computed from
  the value link it to an earlier entry, never the engine's fingerprint (rule, file, text before it), so changing a
  value in place fixes the old one and opens the new one, and a PR that does it introduces it. After changing the
  master key, set `PITANGUS_PREVIOUS_MASTER_KEY` to the one before so secrets keep their entries; without it the old
  entries stay open as unverified, never fixed. The value is read only where everything its engine said about it holds,
  for one value only (Betterleaks' redacted match, length and entropy; Trivy's offset and masked text, line by line
  over a private key) and, beyond a file Betterleaks reads in one piece (100 KB), where it may count columns from the
  middle of any line, only if it is the one value that fits anywhere on its line; one secret reported twice is one
  finding. A secret whose value can't be read for sure is unlinkable: named by its rule, its file and its lines'
  content, it never inherits triage and is never fixed while its engine still reports a secret of that rule in its
  file or another engine that saw it reports one there; nor is a secret named by its value while an engine that saw it
  reports there one it couldn't read. A scan that has no master key and can't keep one (the CLI in a read-only
  container, as in CI) names secrets with a key of its own process: the same commit scanned twice is the same.
- **Structure and common words, never values.** One renderer (`shared/render.py`) takes every text that holds code,
  configuration or an engine's words before anything stores, prints or sends it: snippets (an imported SARIF's snippet
  and context region too, with their lines), the prompt's fragment, engine messages, an imported SARIF's rule texts,
  step details, progress, limitations, engine errors and what a failed scan logs, whichever engine or import produced
  them. It doesn't look for credentials and never keeps a word for its position: a word (a run of letters, digits and
  `_`, in any script) stays only if it is a common word (of a programming language, of Pitangus's own vocabulary in
  English and Spanish, of code and security writing) or splits entirely, at `_`, case changes and digits, into such
  words and numbers of up to three digits; every other word becomes `***`, be it a key, an identifier, an operand, an
  argument, a comment, a string, or a host or path segment of a URL. Punctuation and operators stay, so code still
  reads (`cur.execute("SELECT k FROM t WHERE v = '***'" + q)`). A URL in a text also loses its user information and
  every query and fragment value. So does every URL stored or shown, with no exception: a web finding's location, a
  run's target, the pages a scan reached and an imported SARIF's references. What a web finding's identity and its
  coverage read is pinned first: each page's key (scheme, host, port and digests of its path pieces and query, never
  their text), so a page keeps its identity across scans, path templates span scans as before, and two pages shown
  alike stay two. zizmor's findings keep only their route in the workflow, never its YAML. A
  finding's identity (and its identity anywhere in the repository, for the pull request gate) is computed from the
  original first, so nothing looks new, fixed or moved. The values the secret engines detected are also replaced
  wherever they appear, in their encodings; secret findings and hard-coded credentials (CWE-798, 259, 321, 522) keep
  no snippet. What Pitangus's own rule catalog or a public advisory says is shown as published. The panel, database,
  reports, SARIF, `--format prompt` and `/api/findings/prompt`, Jira, notifications and logs all get the rendered
  text: a value survives only if it is made entirely of common words and numbers of up to three digits; no run of four
  or more letters and digits of any other value appears in any of them, in any format, through any engine (a property
  test with a fragment oracle, also run nightly with new examples).
- **Changing the configuration never fixes a finding.** Every scan records which engines were on and which rules each
  applied, with a digest of what each rule matches. A finding is fixed only by a scan in which its engine was on and the
  rule that found it ran, unchanged since the finding was last seen. Turning a rule off (opt-in, custom, third-party),
  turning an optional engine off or updating a rule leaves its findings **Unverified (configuration)**, in every
  coverage mode, and the finding names the rule or engine; a secret a new allowlist entry or disabled rule filters is
  excluded with that reason. The fix hold records and shows why it held, and neither Jira nor the notification channels
  hear about a held or unverified finding.
- **A second look at every secret.** A match that can't be a secret is set aside and counted by reason in the scan,
  never dropped silently: a reference or template, an environment variable's name, a placeholder (`YOUR-ACCESS-TOKEN`,
  `XXXXXXXX`, `12345678`), a key that is public by design (a Supabase anon or `sb_publishable_` key; `service_role`
  keys always stay) and an unsigned JWT. With it, `generic-password` is on by default: on 18 public repositories it went
  from 1,525 matches to 23 and kept all 12 that an independent review labeled real (of the 23 kept, 12 are real and 18
  real or seed data). Long passwords of one kind of character (16 or more), accented letters (`Contraseña2024!`) and
  passphrases (`correct-horse-battery-staple`) are never set aside, and on minified lines over ~125 KB each match is
  read at its own place. On the same corpus the default secret rules went from 246
  matches to 134 with no real secret lost. Secrets in tests, docs or examples are still findings, at **Attend**.
- **The pre-commit hook scans what you're about to push**: the pushed commit as git holds it, compared with what the
  remote already has. An untracked file or an uncommitted edit can no longer block a push. `pitangus scan` gains
  `--commit REF` and `--staged`, and a `--base` that doesn't exist says so before anything is scanned.
- **Third-party code copied into a repository is set apart, by its folders and content.** SAST matches in dependency
  and static library folders, minified files and files opening with the licence banner of a known library (name,
  release, licence, at least 8 KB) are listed under **Excluded** with the reason, never dropped or fixed; a file's name
  never decides, so your own `lodash-helpers.js` or `chart-core.js` is analyzed.
- **Nothing committed is skipped silently.** Every committed file goes through the secret scanners whatever folder it's
  in; SAST and the other engines leave out only dependency folders (`node_modules`, `vendor`… anywhere) and build output
  (`dist`, `build`, `target`… at the root, next to a build manifest or holding source maps), and each such folder is
  listed as not analyzed with its reason. Opengrep's own hidden ignore list is replaced: only test code (`test/`,
  `tests/`, `*_test.go`) stays out of SAST, declared. Betterleaks' and Trivy's own skip lists are off too (dependency
  folders, lockfiles, tests, examples, Markdown, images, `jquery*.js`…): only your secret detection settings leave paths
  out, reported as excluded. Neither engine is trusted to have read everything: each one's log names every file it read,
  and a committed file it didn't name is listed as not analyzed by that engine, so a secret it saw there before is
  never taken as fixed. A `gitleaks:allow` / `betterleaks:allow` comment is honoured for both engines and never silent:
  every match it allows is excluded with its file and line (never its value), counted in the step, the limitations, the
  CLI and `--format prompt`; `PITANGUS_SECRETS_IGNORE_INLINE_ALLOW=1` ignores those comments.
- **Measured SAST rules.** `appsec.js.dom-xss-sink` is off by default (3 of 18 matches were XSS on the measured corpus;
  `PITANGUS_SAST_OPT_IN_RULES` turns it on, and it no longer flags copying another element's `innerHTML` or sanitized
  values). `appsec.java.hardcoded-password` no longer flags paths, parameters, headers, patterns, salts or property
  keys (9 of 9 on the corpus).
- **Invariant tests.** `tests/test_invariants.py`: the registry against the truth, failure injection identical for every
  engine adapter, identity and merging properties (Hypothesis, deterministic on pull requests, random every night in
  `.github/workflows/nightly.yml`), with what still fails recorded until the next phases close it.

- **A session check for scans with saved headers.** An administrator can give a domain a **Session check page**: an
  HTTPS page on it that only opens signed in. A scan that sends the saved headers requests it with them before it
  starts and when it ends; a redirect, 401, 403 or no answer leaves the run incomplete, so an expired cookie no longer
  marks what was behind the login fixed. `POST /api/domains/session-check`; the domain listing adds `session_check`
  for administrators (Alembic `0015_domain_session_check`, applied at start-up).

### Changed

- **The full web scan (ZAP, katana, subfinder) is experimental** and stays off by default (`PITANGUS_DAST_ENABLED`). The
  panel marks it so; a domain's scan button opens the exposure check. Turning it off fixes nothing it found before.
- **Malicious packages by the kind of advisory.** The advisory's type decides (an OpenSSF `MAL-` advisory, which is how
  GitHub's own malware advisories reach OSV, or a database's malware type); otherwise two of three signals must agree (a
  malicious-code CWE, the title, the description), and one alone never decides. This catches compromised releases no
  database types as malware (ultralytics 8.3.41, strong_password 0.0.7, bootstrap-sass 3.2.0.3, `ctx` 0.2.6), in Trivy,
  OSV-Scanner and Grype: critical, Act now, removed rather than upgraded. Advisories on the same package version merge as
  an alias graph (PYSEC↔GHSA↔CVE chains are one finding), a malicious version is a single finding listing every
  advisory, and a duplicate fingerprint no longer loses the verdict. On the OSV databases: 625 malware advisories
  against 606 with the previous rule, 23 more and 4 fewer (a credentials leak tagged CWE-509 among them). Image scans
  keep the removal guide for malicious packages.
- **Checkov and Grype are optional, off by default** (`PITANGUS_CHECKOV_ENABLED`, `PITANGUS_GRYPE_ENABLED`). Off, an
  engine shows as not run (disabled) in the plan, the scan and the report, never as clean, and what it found before
  stays open: turning an engine off never fixes anything.
- **Betterleaks replaces Gitleaks for secrets** (1.9.0, MIT, from Gitleaks' own maintainers; image pinned by digest).
  It takes the same generated configuration (custom rules, disabled built-ins, allowlists), keeps `--redact` and the
  report format, and brings 463 built-in rules instead of 222. A disabled rule it no longer has is dropped from the
  settings. A secret's identity (the HMAC of its value) doesn't change with the engine, and what was found under
  Gitleaks' name is Betterleaks' to prove gone: it's never fixed by the switch. Opt-in validation of active secrets
  (`PITANGUS_SECRET_VALIDATION`, off by default): an active secret is acted on first, a revoked one tracked, none hidden.
- **Linking an image and a repository no longer needs a scan first.** The picker lists the repositories the GitHub
  App or a connected token reach, not only the analyzed ones, and **Link an image** on every repository's row opens a
  dialog that lists the images and links the chosen ones in place; the link holds once the repository is analyzed. The picker's list floats over the page, so a list that
  clips its content (the Images rows) no longer hides it.
- **Getting started checks off what you did anywhere.** Each step comes from the state it stands for: a GitHub token
  counts as connecting GitHub, an incomplete scan or an import counts as an analysis, and pull requests reviewed by the
  GitHub Action count as watched.
- **The status filter of a repository's findings offers what each tab holds.** In **Open**, choosing **Fixed** showed
  nothing (fixed findings have their own tab); now it isn't offered there, and **All** adds **In excluded paths**.
- **A finding is only fixed where the scan looked, and keeps its identity when its name changes.** A complete code
  scan no longer fixes a finding in a file it didn't analyze: left out of the snapshot for its size, or skipped by the
  engine that reports it (the run stores them as `unexamined`). Each finding declares the units it lives in (`units`:
  its file; a dependency's, its project, the manifest together with its lockfile, and every other place it was seen),
  and the registry compares those units, not paths, with what each engine examined (data migration
  `registry_coverage_units` derives them for stored findings). A zizmor finding is keyed by the workflow YAML it
  points at instead of its line, an image history finding by the step's command instead of its position, and an
  advisory that gets a CVE after its GHSA stays the same finding; Trivy and Grype compare image package names as each
  writes them (Java's `group:artifact`, Go's `go1.22.1`), and a report that becomes part of another folds into it
  instead of being marked fixed. State, triage, Jira issue and pending verification follow in every case.
- **`nosemgrep` comments are recorded.** Opengrep runs with `--disable-nosem`: a match silenced in the code is listed
  under **Excluded** with that reason (and counted in the run's limitations) instead of disappearing, reopens if the
  comment goes away, and adding the comment doesn't change the finding's identity.
- **A web finding is fixed only with its own tool's evidence, on that page, in that run.** nuclei's per-URL statuses
  come from its stored responses, extracted inside the container, and ZAP's from its sites tree. Evidence is a
  whitelist: a 2xx means present, a 404 or 410 means absent, a redirect proves nothing (and isn't held against the
  site), and every other status (406, 418, 400, 999, 5xx, no answer…) is a refusal. A finding about one path is fixed
  only when its tool got 404 or 410 there, so WAF codes, challenges served with 200 and catch-all pages never fix it,
  and blocking is judged from every tool's answers over the whole run: a WAF or rate limit that starts mid-run, or only throttles sensitive paths, leaves the run
  incomplete instead of fixing findings. A web tool that didn't finish opens nothing and proves nothing; testssl.sh no
  longer reports from an unfinished scan.
- **The exposure check is sharper.** It also probes plain HTTP on port 80, requesting every URL over its own scheme
  (`-nfs`) and attributing each answer only to the URL it fetched, drops matches on paths the site answers like any
  random path (soft 404 and catch-all pages, also when the page echoes the requested path), treats `//path` as `/path`, counts each page once, checks `/.env` and
  `/.git/config` with its own templates, and no longer marks full-scan findings unverified. A path finding's identity no
  longer depends on other rules' URLs; progress messages no longer mention ZAP or crawling, and the docs and panel name
  debug and status consoles instead of admin panels.
- **No SAST without Docker.** The internal Python checks that ran when Opengrep couldn't are gone: without Docker the
  SAST step is **Not tested** (and the run incomplete) instead of a few checks passing for coverage.
- **Rule tests.** Each Opengrep rule has cases in `rules/tests/` (`ruleid:` lines it must match, `ok:` lines it must
  leave alone), including the false positives fixed in this release; `make rules-test` runs them and so does CI.
- **Fewer false "fixed" and less noise from the engines.** A finding is only marked fixed when the scan could have seen
  it: Checkov ending with an error or files it couldn't parse, a SARIF import of another category (CodeQL uploads one
  per language) and an engine that didn't run (`not_tested`) no longer close anything; a web scan closes a ZAP finding
  only if its page was reached this time, and sign-out links are left out of the crawl when the scan carries a session.
  A response header the whole site shares (CSP, HSTS, X-Frame-Options…) is one finding per host instead of one per page,
  redirects aren't part of the URL inventory, and a file name with a build hash (`index.CSY8UEx1.js`) keeps its
  finding across deploys. nuclei's technology detections are kept only at the root or as information, and a host pass
  that times out keeps what it found.
- **Engines that see more and say what they skipped.** Opengrep follows tainted data between functions of a file
  (`--taint-intrafile`), reads files up to the snapshot's 2 MB limit and lists the ones it skipped, with two jobs;
  Razor, ERB and JSP views count as languages without rules. Two secrets on the same line are two findings, and one
  package in several lockfiles of a monorepo lists every location. Operating system packages take their severity from
  the distribution, as Grype does, the fixed version offered is the lowest one that fixes, identical lines in a file
  are separate SAST findings, and OWASP coverage counts only the rules of the repository's languages. Three rules lost
  false positives (command injection only from `child_process`, `verify=False` only on HTTP calls, Go path traversal
  only from handler input).
- **One engine's trouble stays where it is.** A dependency resolution a remote repository refuses (a 429 from Maven
  Central on a parent `pom.xml`) no longer blinds Trivy: it runs again without remote resolution and resolves each
  Maven manifest on its own, and only the manifests that still fail are unexamined, for dependencies only. OSV-Scanner
  no longer claims to have examined everything when it read no lockfile. A manifest an engine couldn't resolve isn't
  counted as examined: packages left without a version (a parent POM that didn't resolve: 7 advisories instead of 81
  for a Spring Boot project without network), a manifest without the lockfile its engine needs and a UTF-16 lockfile
  leave it unexamined for dependencies, and the Trivy and OSV-Scanner steps name it. An engine run that didn't finish (killed,
  timed out, wrong exit code, empty, truncated or invalid output, no completion mark) opens and fixes nothing in every
  coverage mode; the rule lives in the engine contract and is fault-tested on every adapter. Coverage is per file even
  when an engine ends partial: a partial Opengrep run proves gone what was in the files it read.
- **Folding findings never relaxes triage.** When several fingerprints fold into one finding, copies that agree keep
  their decision with the earliest expiry, and copies that disagree or were never reviewed send it back to open with a
  note; every copy's history and every Jira issue are kept.
- **The pull request gate counts like the findings register.** On the server and in `pitangus scan --base`, both sides
  are grouped with the same identity and copy count: moving, reformatting or commenting a vulnerable line is not
  introduced, pasting one more copy is exactly one, and a review never changes the main branch's findings or counts.
  The gate counts across the whole repository and follows renamed files (GitHub's `previous_filename`, `git diff -M`):
  moving a vulnerable line to another file or renaming a file is neither introduced nor, in `scan --base`, fixed;
  copying a line into another file introduces one. Findings in the register are still stored per file.
- **Kinds of web scan keep their own findings.** A full scan followed by an exposure check no longer moves the full
  scan's findings to the exposure check (keeping when they were first seen), and alternating no longer moves them back
  and forth: web fingerprints name their kind of scan in every identity mode, the registry follows former fingerprints
  only within the same kind, and the dashboard's trend counts each kind on its own.
- **Honest terminal output.** The verdict counts the rows it shows; counts agree in English and Spanish, stored runs
  included; each engine that didn't run is named once and a disabled one is never announced; prompts for AI assistants
  never point to the panel's Reverify; files an engine couldn't read are listed with a localized reason; a lockfile
  from which the engine listed no package is listed as not examined (lockfile without packages). `make engines` pulls only the engines this server runs plus the exposure check's tools, and
  `make engines LIST=1` lists them.
- **Trivy's databases are refreshed once, under a lock.** Several workers updating the same cache at once crashed a
  scan (SIGBUS); now one refreshes them and the scans run with `--skip-db-update`.

- **A transitive dependency's fix says who brings it in and what to update if it stays below, in any ecosystem.**
  The scan reads the dependency graph Trivy resolves from the lockfile (npm, yarn, pnpm, Poetry, uv, Cargo, Go,
  Composer, NuGet, Bundler…) and stores on each dependency finding which package requires it and which direct
  dependency is at the top, whichever engine reported it. The guide, the Jira issue and the reports start with the
  whole move ("Update rustls-webpki to 0.103.13; if it stays below, update reqwest, which brings it in"), with the
  manager's commands in order. Dependency guides for most managers also get a command that shows which version ended
  up installed (`poetry show`, `npm ls`, `cargo tree --invert`…). Findings get this from their next scan.
- **Jira issues a developer can act on, labelled when a scan verifies the fix.** The title says what to do and where
  (`High · starlette 0.37.2 → 1.3.1 · org/api (poetry.lock)`, or the finding with its repository and file) instead of a
  severity and a vague summary, and the description starts with the change, the file, the command and how to check it;
  why it matters (severity, deadline, KEV, EPSS when it is high) and the details come after. When a scan verifies a fix,
  Pitangus comments and adds the destination's label (`pitangus-fixed` by default, filterable in Jira); it moves the issue
  to a status only if an administrator picked one of that workflow for the destination, since every team closes issues
  its own way. A destination also sets the language of its issues. The rule form shows how the most severe issue will
  read before saving, and a finished backfill links the issues it created and groups why others failed.
- **Excluded paths and secret detection settings say what they do before you save.** The excluded paths dialog has a
  visible label with what each pattern covers, says the reason is required, and previews which findings would move to
  Excluded (or back to open) while you type, checking the patterns as saving does (`POST /api/assets/exclusions/preview`).
  The secret detection dialog starts with what people reach for: silencing test or fake secrets (by path, word or
  expression), then turning off a noisy built-in rule, then their own detectors; each list states its limit and the
  dialog points to Policies for the defaults.
- **No promise of a fix the tool doesn't have.** The README and the docs say a finding's fix is what the tool knows (a
  command, an example to adapt, the scanner's own advice), not an exact fix for every finding.
- **Threat model import keeps everything and shows it.** A model an AI assistant wrote imported with 55 warnings and
  lost most of its data. Now saved means shown: descriptions of flows and boundaries are stored, editable and in the
  reports; **assumptions** are a section of every model (the new **Context** tab, at the start of the report); any field
  Pitangus doesn't know becomes a **custom property** of its object (editable in the inspector and dialogs, a tooltip
  on the diagram, an appendix of the report, exported back in place), and the model's own unknown sections show as
  tables or lists. Synonyms are read as our fields (`component_id` → `element`, a threat's `description` →
  `scenario`, a tree's `name` → `goal`, `status: potential` → `relevant`, `severity: crit`…), documented in the JSON
  Schema (`x-pitangus-aliases`, `x-pitangus-synonyms`) and the AI prompt. Your own severity, likelihood, impact,
  difficulty, mapping status and category are kept as new options (a custom severity sorts after ours unless it has an
  equivalent, `level_equivalents`); only a template's own vocabulary stays strict (STRIDE's and LINDDUN's categories,
  PASTA's stages, AND/OR gates), keeping the value as a property with a warning. An unknown approach imports as Custom,
  and a Custom model turns on the module of any section it brings. Problems have three levels (error, warning, info)
  and a `code`: the importer counts errors and warnings, groups identical problems ("… in 15 flows") and folds the
  minor adjustments. A custom property over 8,000 characters per object is an error instead of a silent drop.
- **The full MITRE ATT&CK Enterprise catalog, offline.** Every technique and sub-technique of ATT&CK v19.2 is
  recognized with its official name and tactics (bundled from MITRE's STIX data, pinned by SHA-256; `make
  attack-catalog` refreshes it). An ID not in ATT&CK warns "not found in ATT&CK v19.2", a revoked one names its
  replacement. Tactics follow v19.2 (TA0005 is now Stealth, TA0112 Defense Impairment), and T1562, revoked, is
  replaced by T1685 in our suggestions.

### Fixed

- Two engines' reports of one problem folded into one finding no longer lose the folded one's fingerprint: if its engine
  failed in an earlier scan, its entry moves to the finding instead of being marked fixed.
- Two resources a configuration engine reports without an address (two Kubernetes Deployments in one file) are no
  longer deduplicated into one: the second is kept among the finding's places.
- Go advisories reported as `v0.3.7` by Trivy and `0.3.7` by OSV-Scanner are one finding.
- A RubyGems fixed version written as constraints (`~> 6.1.7, >= 6.1.7.1`) no longer offers a version below the installed
  one.

- **Credential files are scanned for secrets.** `.env*`, `.npmrc`, `.pypirc`, `.netrc`, `id_rsa`, `credentials`,
  `.git-credentials`, `.dockercfg`, `.s3cfg`, `.boto`, `.htpasswd` (dot folders such as `.aws` included) were left out of
  every scan. Now Betterleaks and Trivy's secret scanner read them, from a folder of their own no other engine sees,
  deleted as soon as they finish.
- **Trivy's databases are refreshed in a folder of their own** and replace the live ones only when they arrived whole:
  a refresh that ran out of space (the Java database) deleted the one in use.
- **A pull request that pastes a problem above an identical one introduces it.** The gate counts instances per finding
  family (Opengrep, secrets, zizmor, SARIF) instead of checking whether the fingerprint exists.
- **A SARIF from a failed run fixes nothing** (`executionSuccessful: false`, or no results list).
- **Concurrent image scans** no longer fail on Trivy's shared layer cache ("cache may be in use"), and an engine failure
  is no longer reported as "couldn't read the image from the registry".

- **Web findings stored per page no longer turn "fixed" after the change to one finding per host.** The first web scan
  of this version marked fixed the header, CSP and hashed-asset findings it now groups (105 on pitangus.dev), although
  nothing had changed. Each grouped finding carries the fingerprints it had per page, and the next scan folds those
  entries into it, fixed ones included, with their triage.
- **Fewer false "fixed" where a tool didn't look.** A file on which an Opengrep rule ran out of time counts as not
  analyzed; a nuclei finding on a page is only fixed if its page pass requested that page; a scan with saved headers
  and no session check page fixes nothing it found with them.
- **Trivy's misconfiguration checks are refreshed once too.** Concurrent scans updating the checks bundle failed with
  "mapfs file copy error"; it's now refreshed under the same lock as the databases, and scans run with
  `--skip-check-update`.
- **Grype analyzes the platform Trivy did.** On an ARM host the two engines analyzed different platforms of a
  multi-platform image and their results were merged; Grype now gets `--platform` from what Trivy read, and its step
  names it.
- **A Slack token both engines see is one finding** (Gitleaks' `slack-bot-token` and Trivy's `slack-access-token`), without
  making Gitleaks' rule switch off Trivy's broader one.
- **The same comment or `Cache-Control` value on every page is one finding** per host and value, instead of one per page
  (404 pages included).
- **Rules.** A string concatenated between quotes (`"... = '" + name + "'"`) in Python and Go SQL is caught; a literal
  after a space in `dangerouslySetInnerHTML={{ __html: "…" }}` no longer is. Every rule now has a case it must match and
  one it must leave alone (`rules/tests`), checked by the test suite and by `make rules-test`.
- **`pitangus scan` names an optional engine that didn't finish** (Checkov, zizmor) under "Not analyzed".
- **Evidence: domains no longer go into the consolidated SBOM and VEX.** A web scan lists no packages, so a domain
  showed up in the portfolio SBOM as an empty application and was counted as "with a completed full scan". The SBOM
  and VEX (consolidated and per asset) now come only from repository and image scans; a domain stays in the audit
  evidence. The scope summary counts every asset in scope (repositories, images and domains, the same number the
  picker shows), says how many the SBOM and VEX include and which ones are left out and why. `GET /api/evidence/scope`
  adds `domains`, and its `complete` (and the one in `GET /api/evidence`) counts only repositories and images.
- **Secrets after non-ASCII text are read where they are.** Betterleaks counts columns in bytes and Pitangus read them
  as characters, so after an `ñ` or in a minified bundle the secret filter, the identity, the context and the masking
  read other text (23 false critical findings in Pitangus' own panel bundle). Columns are now converted, and when they
  still don't land on the match (big files are scanned in fragments) the nearest occurrence is used, as Betterleaks does.
- **A web finding seen by one kind of scan is never fixed or absorbed by another.** The kind of scan (anonymous crawl,
  saved headers, API definition, exposure check) is part of a web finding's identity, so an anonymous crawl no longer
  fixes what only a signed-in scan can see on a sibling page.
- **The dashboard doesn't count a renamed finding as fixed and new.** A fingerprint that changed (an engine's new one,
  or the identity that replaces it in v2) keeps its history: no false fix, no false new finding, no MTTR from it.
- **Checkov files it couldn't parse and doesn't name** leave its run inconclusive instead of proving every file.
- **The nightly property run works.** Its workflow file wasn't valid YAML, so it never ran; it now runs the invariants
  and every property suite with thirty times the examples.

### Known limitations

Measured during the release validation and documented, not fixed in 0.14
([scanning-code.md](docs/scanning-code.md#known-limitations-in-014), [scanning-web.md](docs/scanning-web.md#limits-and-timings)):

- `appsec.js.route-without-auth`: false positives with routers mounted with authentication in another file, Fastify's
  `addHook('onRequest')` and FastAPI's `APIRouter(dependencies=[…])`; a false negative with `app.use('/admin', auth)`;
  no coverage for Next.js or NestJS.
- The policy reader misses writes protected only by data validation, `if true || …`, `using (true)` / `with check
  (true)` and views over `auth.users`, and reports a table whose RLS is enabled inside `DO $$ … $$`.
- `appsec.js.public-env-secret` misses `*_KEY` names without `API_`, `process.env["…"]` and destructuring.
- A `pyproject.toml` that only configures tools (no dependencies) and has no lockfile beside it is listed as not
  examined for dependencies (no lockfile): Pitangus doesn't read declarations to tell, so it errs on the side of not
  examined. Nothing is fixed or opened by it.
- Web: an intermittent exposure is dropped; a single connection error from testssl.sh or nuclei leaves the host
  incomplete (conservative); `nginx-eol` is one finding per page in the full web scan; a 200 challenge served on every
  path, the root included, can stand in for the root's headers; the blocking thresholds were calibrated on local sites
  only.

## [0.13.1] - 2026-10-11

### Added

- **A full demo organization.** `make demo FULL=1` (`pitangus demo --full`) builds Lapis Labs, a made-up company, so
  every view has something to show in screenshots and trials: five repositories with a month of scans (trends, fixed
  findings, MTTR, due dates), a pull request review, a container image, a domain verified for the demo
  (`tienda.example.com`, with scope, weekly schedule, test user, technologies and two passive web scans), a pending
  one, two members and a few triage decisions. It runs offline: findings are engine outputs recorded against the
  bundled samples, replayed through the normal parsers, registry and triage, with the KEV and EPSS feeds already on
  disk (none are downloaded). Everything is marked as demo, it never notifies channels or Jira, its runs don't tick
  "first analysis" in Getting started, and running it again adds nothing. It writes next to the workspace's real data
  and nothing removes it: use a trial install.
- **Documentation for newcomers** at docs.pitangus.dev, in English and Spanish: what Pitangus is, key concepts, a
  glossary and FAQ, scanning code, images and websites/APIs (passive DAST, domains, scope, test users), findings,
  compliance, threat modeling and upgrading. The old features page is split among them. Screenshots of the panel in
  light and dark, taken from the demo organization, and an up-to-date architecture diagram (SVG in light and dark;
  the Mermaid version stays for GitHub).

### Changed

- **Demo domains are never asked or scanned.** A domain the demo registers under a name reserved for examples
  (`example.com`, `example.net`, `example.org`, RFC 2606) skips the daily proof re-check, and its schedule moves on
  with a note instead of queuing one. The API answers `409` to a web scan (`POST /api/domains/scans`, before any DNS
  lookup) or a search for related hosts (`POST /api/domains/discover`) of one.
- **The documentation site** carries Pitangus' identity (the manual's tokens, IBM Plex, its own code theme), sends
  security headers (`_headers`: CSP by hashes, HSTS, COOP, Permissions-Policy, checked at build time), publishes
  `llms.txt` and `llms-full.txt` in both languages, a `robots.txt` that names AI crawlers, JSON-LD and each page's
  last update in the sitemap. It is published from Cloudflare (Workers Builds, branch `main`); the GitHub Pages
  deployment is retired.

### Fixed

- **Day labels on chart axes** no longer overlap: the last day, aligned to the edge, always keeps its label, and one
  that would come too close to it is dropped.
- **The heading of each wizard step** still receives focus (for screen readers) but no longer shows a focus box.
- **A link in the same tab** (a domain's "New scan" or "Import results", Back and Forward) now preselects the domain
  and the type in the new-analysis wizard, without remounting a wizard already in progress.
- **The OSV hint** in the new-analysis wizard says that package names and versions also go to deps.dev, and that
  Trivy and OSV-Scanner check dependencies offline anyway. The README names the **Reverify** button as the panel does.
- **CI:** the docs build fetches the full history (each page's "Last updated" date) and restores nothing from the
  package manager's cache; the manual Cloudflare workflow restores no cache into the job that holds its token.

## [0.13.0] - 2026-10-10

### Breaking

- **Domains API.** `DomainRow.schedule` is an object (`frequency`, `weekdays`, `month_days`, `time`, `timezone`,
  `next_run_at`, `last_run_at`, `last_run_id`, `note`, `test_users`, `use_headers`); the flat `schedule_next_at`,
  `schedule_last_at`, `schedule_last_run` and `schedule_note` are gone. `POST /api/domains/remove` answers
  `runs_kept` instead of `runs_deleted` (see Changed).
- **New engine images.** With `PITANGUS_DAST_ENABLED=1`, run `make engines` after upgrading: subfinder, katana, nuclei,
  httpx and testssl.sh join ZAP (each pinned by version and digest). nuclei's templates are downloaded once by the
  worker from GitHub (release pinned by SHA-256).

### Added

- **Test users per domain.** A domain's **Test users** tab keeps reusable accounts (username and password, or with a
  TOTP seed), encrypted at rest and never answered back; a web scan (or a schedule) picks up to 3 and ZAP signs in
  with them through its browser-based authentication. Secrets reach ZAP only on standard input: never in `docker
  inspect`, the command line, the host's disk or the logs. Before crawling, each sign-in is checked on its own (ZAP's
  authentication report, and an optional check page that must answer 200); a user who can't sign in isn't crawled as,
  and the run is marked partial coverage so "few findings" never reads as clean.
- **Command palette and keyboard shortcuts.** `⌘K`/`Ctrl+K` searches pages, analyses, repositories, images and domains
  and runs actions (New analysis, Import SARIF, Add domain…); `G` + a letter jumps to each page, `N` starts a new
  analysis and `?` lists the shortcuts.
- **OWASP guidance on every finding.** A curated, versioned mapping (`pitangus/modules/findings/references.yaml`,
  reviewed against the published indexes) links each finding to OWASP Cheat Sheet Series pages, its OWASP Top 10:2025
  category and, for code and web findings, the API Security Top 10 2023 risk and the WSTG v4.2 test that fit: by rule
  (ZAP, nuclei, testssl.sh, zizmor and container image checks), framework or file, CWE (100 CWEs, among them every one
  our rules and engines emit) and scanner. Served as `guidance: [{title, url, kind}]` on findings (computed when read,
  so old runs get it too), shown under **OWASP guidance** in the finding's detail after the tool's own references, and
  printed next to each finding's references in the technical PDF and the Markdown report. Links only; the tool's own
  guidance stays first and verbatim. A finding whose engine set no OWASP category (nuclei, testssl.sh, imported SARIF
  without tags) now gets its Top 10:2025 category from OWASP's CWE mapping when served; the technical PDF shows it next
  to the CWE.
- **Known vulnerabilities of the versions a site exposes.** After httpx, a passive web scan looks up the versions it
  read of well-known packages (Flask, Django, Werkzeug, Express, Next.js, jQuery, Bootstrap, AngularJS, Lodash… an
  explicit table, `web_versions.PRODUCTS`; at least `major.minor`) with OSV-Scanner 2.6.0 offline, on a CycloneDX SBOM
  of package URLs and the OSV databases in `data/osv-cache` (the same as dependency scans and the advisory watch);
  KEV and EPSS come from the local CVE copy (`cve_db.signals`). One finding per product and version (tool
  `httpx + OSV`, scanner `dast`, CWE-1395, confidence 5, "Flask 2.2.3 has known vulnerabilities") with every CVE and
  GHSA, the worst severity, the highest of the advisories' fixed versions and their references; a JavaScript library
  ZAP already reported at that version (10003) isn't repeated. New step `dast-versions` and a limitation saying the
  version isn't verified; when OSV-Scanner can't run, the step says why and earlier findings aren't marked fixed.
  Apache httpd, nginx, OpenSSL, PHP and other servers aren't looked up (no OSV package and no CPE ranges in the local
  CVE copy): the step lists them as not looked up.
- **ZAP's AJAX spider.** After the classic spider, the plan runs `spiderAjax` (one headless Firefox, 2 minutes, depth 5,
  100 states) from the domain's URL and again as each test user that signed in. It clicks links only (`elements: [a]`,
  no default elements, no random inputs), keeps to the context with a strict scope check and avoids logout links. The
  passive step says how many URLs it found, and ZAP's time limit grows 3 minutes per AJAX spider. Without test users
  ZAP's home stays `noexec`; only `/home/zap/.ZAP/webdriver`, a tmpfs of its own, lets geckodriver run.
- **ZAP's passive rules, explicit.** A `passiveScan-config` job opens the plan: passive scanning only inside the scope
  (`scanOnlyInScope`), every rule of the image at its default, and PII disclosure (10062), debug errors (10023),
  sensitive information in URLs (10024) and the Referer (10025), suspicious comments (10027), vulnerable JS libraries
  (10003) and the version-leaking header and banner rules set at Medium. The image bundles `pscanrules` and `retire`,
  not `pscanrulesBeta`/`pscanrulesAlpha`; those aren't installed at scan time.
- **Scheduled scans sign in as test users.** The schedule rule (`POST /api/domains/schedule`) takes `test_users` (up to
  3 ids, each signing in on a host of the saved scope) and `use_headers` (409 without saved headers); the panel picks
  them under the schedule in a web scan's review and on the domain's page. When the scan runs, a user deleted since is
  dropped from the rule, one now outside the scope is left out of that run, and missing headers aren't sent: the scan
  runs with the rest and the run and the schedule's note say what was left out. Stored in the existing
  `schedule_rule` JSON (no migration); rules saved before read as no users and no headers.
- **Outgoing address for sites that filter by IP.** New setting `PITANGUS_EGRESS_IPS` (IP addresses or CIDR ranges,
  comma-separated, validated at start-up); `GET /api/domains` answers it as `egress`. Without it, an administrator can
  detect the server's address once (`POST /api/domains/egress`: one HTTPS GET to `api.ipify.org`, no redirects, kept
  in the settings documents). The review of a web scan shows "If your site filters by IP, allow …" with a copy button,
  replacing the firewall/WAF fold.
- **Domains list and page.** "Add domain" sits next to the page title, a search filters the list ("Showing N of M"),
  and the whole row opens the domain. The domain's Overview ends with a **Disconnect domain** section that says
  exactly what is deleted; the action left the page's "…" menu.
- **Passive web scans run four more tools, still without attacking.** With their images pulled (`make engines` with
  `PITANGUS_DAST_ENABLED=1`; each pinned by version and multi-arch digest), a `dast_scan` runs katana 1.7.0
  (`projectdiscovery/katana`, a crawl with a headless browser whose in-scope URLs, without query strings, are stored
  with the run as `web_inventory` and handed to ZAP through an `import` job and to nuclei), ZAP, nuclei 3.11.1
  (`projectdiscovery/nuclei`) with nuclei-templates 10.4.9 downloaded once by the worker (SHA-256 pinned) and filtered
  to detection-only templates (GET/HEAD, no body, no fuzzing, no out-of-band calls, no attack markers or tags; CVE
  templates read fixed paths only), testssl.sh 3.2 (`ghcr.io/testssl/testssl.sh`, the project's own image; protocols,
  ciphers, certificate, HSTS, no vulnerability checks) on the first 3 hosts, and httpx 1.12.0
  (`projectdiscovery/httpx`), whose technologies land in the run's `summary.technologies` and on the domain's page
  (`last_scan.technologies` in `GET /api/domains`). Every tool runs in the hardened container with the scan's pinned
  addresses only, a dead resolver for ProjectDiscovery's own DNS client, at most 10 requests a second and a hard
  timeout; katana and nuclei get the saved headers on standard input when the scan asked for them. Each tool has a
  step (`dast-katana`, `dast-nuclei`, `dast-testssl`, `dast-httpx`: completed, partial or skipped with the reason); a
  tool that fails leaves its step partial, the scan goes on and its earlier findings aren't marked fixed. When ZAP,
  nuclei or testssl.sh report the same problem at the same URL (an explicit table: security headers, cookie flags,
  HSTS, deprecated TLS and weak ciphers, certificate problems, exposed `.git` or `.env`) it's one finding with
  `also_detected_by`, `related_rules` and each tool's evidence in `web.also`. The panel names every tool on the run and
  its findings, shows what the other tools saw on a web finding, a **Skipped** step state, and the technologies on the
  domain's page.

- **Related hosts and a scope saved per domain.** Adding a domain (with `PITANGUS_DAST_ENABLED=1`) queues a discovery
  job: subfinder 2.16.0 (`projectdiscovery/subfinder`, pinned by digest, pulled by `make engines` with web scans on)
  asks passive sources for names under the domain, with no API keys and a hard timeout, in the usual hardened container.
  Names that aren't a valid host under the domain, or that resolve to any private, loopback, link-local or metadata
  address, are dropped. Hosts land in the new `domain_hosts` table (migration `0013_domain_scope`) out of scope, with
  first and last sighting. `GET /api/domains/scope` lists them with the last round's state; `POST /api/domains/scope`
  (`set`, `add`, `remove`, `exclude_all`) saves the scope, only for DNS-verified domains (409 otherwise); `POST
  /api/domains/discover` searches again (202). `POST /api/domains/scans` takes `use_scope`: the worker reads the saved
  scope when the scan starts, pins and crawls its hosts and keeps the excluded ones out of ZAP's context
  (`excludePaths`). Weekly scans use the saved scope too. The panel shows it in the new scan (**Include subdomains**)
  and in a **Scope** tab on the domain's page, replacing the per-scan host list.
- **Domains: more ways to prove control, and a probe.** Besides the DNS TXT record, `POST /api/domains/verify` takes
  `method: "file"` (`https://<host>/.well-known/pitangus-verify.txt` with the token) or `"meta"` (`<meta
  name="pitangus-verify" content="<token>">` in the homepage), fetched once from the host's checked public address
  (certificate validated, no redirects, 10 s and 64 KB at most). The method that proved it is stored and the daily
  re-check asks for the same one. Only a DNS proof covers subdomains. `POST /api/domains/probe` checks a URL before
  registering it (`host`, `reachable`, `https`, `status`, `public`); `/api/domains/check` stays as an alias.
- **Passive web scans: scope, headers, API mode and a weekly schedule.** `POST /api/domains/scans` takes `mode`
  (`web` or `api`), `hosts` (up to 20 subdomains or `*.` wildcards of a DNS-verified domain; each listed host must
  resolve to public addresses and is pinned, wildcards only widen ZAP's context), `use_headers` and, in API mode, an
  OpenAPI 3.x / Swagger 2.0 definition (`spec`, JSON or YAML up to 5 MB in base64, or `spec_url` on a host of the
  scope); it answers `202` with `run_id`. API mode imports only the definition's GET and HEAD operations (others are
  dropped before ZAP sees it), aimed at the domain, refuses remote `$ref` and YAML aliases, and keeps only the
  definition's SHA-256 and operation count (`dast_scan` with `variant: "api"`). Request headers per domain (`POST
  /api/domains/headers`, at most 10, encrypted in the vault, never answered back) are added by ZAP's replacer to the
  scope's requests only; the plan now reaches ZAP on its standard input into a memory-only folder, and the values are
  scrubbed from what ZAP returns. ZAP's container gets `--dns 127.0.0.1`: only pinned names resolve. A weekly passive
  scan per domain (`POST /api/domains/schedule`) is queued by a new periodic task (`domain_scans`, hourly, only with
  `PITANGUS_DAST_ENABLED`); a lapsed proof or a running web scan is recorded as the reason it was skipped, and
  `GET /api/domains` shows the next and last scheduled scan and the latest web scan. A web scan only marks fixed what
  a scan like it had seen (same mode, definition and use of headers) on a host it looked at. Migration `0011` adds
  the proof method and the schedule columns. New runtime dependency: PyYAML (MIT).
- **Strix SARIF.** `import-sarif` places Strix's endpoint findings (anchored to `SECURITY.md` in its SARIF) at the
  endpoint's URL with its method, keeps Strix's severity label, and skips its coverage results; code findings stay at
  their file. Help texts of web findings are redacted like their messages.

- **Passive web scan of a verified domain**, launched from the panel (New analysis → Web application) or with
  `POST /api/domains/scans` (administrators). ZAP 2.17, pinned by digest, crawls the domain for up to 2 minutes and
  runs its passive rules over every response; no active scan, no AJAX spider, no form submissions. Off unless the
  server sets `PITANGUS_DAST_ENABLED=1`. Before it starts, the worker checks again that the domain's proof is current
  and its TXT record still published (gone: the proof is withdrawn), and that the name resolves to public addresses
  only; ZAP gets that address pinned and a context with the host only. One web scan at a time, 15 minutes at most;
  ZAP runs as its image's user with no capabilities, a read-only root, 3 GB and 2 CPUs and an explicit heap. Its SARIF
  goes through the `import-sarif` parser, so a native scan and an import of the same site share fingerprints. A new
  run type, `dast_scan`, is a full scan of the domain: what it no longer reports is marked fixed. It needs the Docker
  runner (the worker image without a socket doesn't carry ZAP and says so), and `make engines` pulls ZAP's image
  (about 1.2 GB) only with the variable on. The residual risk of an engine with network is in
  [security.md](docs/security.md).

- **Bring your own DAST.** `import-sarif` (CLI, panel, `POST /api/ci/sarif` and the Action) accepts the SARIF of web
  scanners (ZAP's `sarif-json` report, Nuclei's `-se`) against a **verified domain** (`--asset domain:<host>`, also
  the host or the domain's id). Their findings get `scanner: dast` (the `Web` source in Findings), the URL without its
  query string or fragment as the location, a fingerprint of rule, URL and parameter name (never the evidence, so the
  same alert doesn't come back as new on every run), and only the method, parameter and a bounded evidence are kept:
  never the request or response the tool attached, which carry cookies and authorization headers. A later full import
  of the same tool marks fixed what it no longer reports, like any import. Importing against a domain nobody vouches
  for (not verified, or the proof ran out) is refused with `409`. Recipes for GitHub Actions with the ZAP Automation
  Framework plan and with Nuclei in [integrations.md](docs/integrations.md#bring-your-own-dast).

- **Domains** (Scanning → Domains). The domain registry that was hidden is now in the panel: an administrator adds an
  HTTPS domain, publishes the TXT record shown (with copy buttons) and verifies it; everyone sees the domains and
  their status, with "Findings" once something was imported against one. The proof counts for 90 days and a daily
  periodic task looks the record up again (present: extended; gone: withdrawn; DNS not answering: nothing changes).
  Removing a domain deletes what was imported against it, and the panel says so before asking. API, administrators
  only for the writes: `GET /api/domains`, `POST /api/domains`, `POST /api/domains/verify`, `POST /api/domains/check`
  (one HTTPS `HEAD` to a public address, no redirects) and `POST /api/domains/remove`; verifying and probing count
  against the progressive lock-out. Storage moved from the `domains` document to the `domain_registry` table
  (Alembic `0010`, data migration `domains_to_table`). Native dynamic testing stays in development.
- **Web findings say what the scanner knows.** An imported or native web finding keeps its rule's description,
  solution, references (http(s) only, at most 8) and WASC ids, and the attack the scanner sent, all bounded and redacted
  (`web.description`, `web.solution`, `web.references`, `web.wasc`, `web.attack`). The panel shows them in order (what it
  is, where, evidence, how to fix it, how to check it, references), attributed to the scanner and as published. Pitangus
  only adds what it derives: the fragment of the evidence the result is about (`fix.web.highlight`, e.g. the
  `'unsafe-inline'` of the `style-src` the message names) and, for rules about response headers, a quoted `curl -sI`
  check (`fix.web.check`). Jira issues and the Markdown and technical reports carry the same.
- **Scheduled domain scans follow a rule.** The weekly switch became a schedule: daily, on one or more weekdays or on
  one or more days of the month (1–28), at a time of day in an IANA time zone (the browser's by default, checked by
  the server), at most once a day per domain. `POST /api/domains/schedule` takes `schedule: {frequency, weekdays,
  month_days, time, timezone}` or `null`; `GET /api/domains` answers it with `next_run_at` (UTC, computed by the
  server; the panel previews the same moment). The review of a web scan has a "Schedule" switch with "Also run now"
  (on by default; off, it only saves the schedule), and the domain's page says the schedule in plain words with
  Change and Turn off. A domain already scanned that local day moves on to its next run instead of a second scan.
  The periodic task looks for due scans every 5 minutes instead of every hour. **Changed:** `DomainRow.schedule` is
  now an object (with `next_run_at`, `last_run_at`, `last_run_id`, `note`) and the flat `schedule_next_at`,
  `schedule_last_at`, `schedule_last_run` and `schedule_note` fields are gone. Alembic `0012_scan_schedule` adds
  `schedule_rule`; the data migration `scan_schedule_rules` keeps existing weekly schedules on the weekday and time of
  their next run, in UTC.
- **Pitangus' own nuclei templates.** `pitangus/modules/scanning/rules/nuclei/` (ids `pitangus-…`) goes through the
  same `allowed()` and page-level split as nuclei-templates, into its own cache folder (named after its digest) mounted
  read-only at `/pitangus` next to the release: open directory listing (CWE-548) and credentials in JSON responses
  (CWE-200) on every page, 26 fixed sensitive paths per host (CWE-200/538), published API descriptions, development
  metadata files, and security.txt as a technology row. GET only, no query strings; each matcher proves the content.
  Their title, description and remediation are stored in English and Spanish.
- **A URL inventory for the web scan.** robots.txt (`Allow`/`Disallow` paths and `Sitemap:` lines) and the sitemaps
  (an index followed down to 5 documents per host) are read by the worker from each host's pinned address, like an
  OpenAPI definition; with katana's crawl, the definition's parameter-free GET paths and every URL ZAP requested (a new
  `export` job in the plan), they make one inventory (in scope, no query strings, up to 500) that ZAP requests before
  its spider and nuclei reads whole. A new step, `dast-inventory`, says what each source added. **Changed:**
  `web_inventory` is now `{sources: {katana, robots, sitemap, openapi, zap}, count, urls}` (no `tool`).
- **The findings table and the technical report group a web problem by rule and title.** One row "CSP: style-src
  unsafe-inline · 3 URLs" opens to each URL (aria-expanded/aria-controls), each with its own fingerprint, triage and
  lifecycle; the table says "15 findings in 8 problems" and the figures still count per URL. The PDF and Markdown
  technical reports give such a problem one action, one sheet or one row with its URLs; the audit evidence keeps one row
  per URL.

### Changed

- **Pitangus' own identity, everywhere.** An identity manual (`.claude/skills/pitangus-brand`, also published as a
  design system) now drives the panel, the PDF/Markdown reports and the threat diagram: cool neutrals instead of cream,
  sulphur yellow only for the brand and the main action, one meaning per color (red critical, orange attention —
  never yellow — green ok, slate info), the sidebar in ink like the kiskadee's crown, IBM Plex type, small radii,
  tables and ruled rows instead of card-wrapped pages, notices without pastel boxes, Phosphor icons (Lucide removed),
  and the same rules in light and dark, checked for WCAG AA contrast. Guard tests block the old patterns.
- **New analysis is a guided flow** with a vertical step rail: type, target (domains and APIs together, with the saved
  scope), access (test users and headers), review (schedule and outgoing IPs).
- **Integrations are sections of rows** (code providers, registries, notifications, issue tracking, AI), each with its
  status and its configuration folded below.
- **Removing a domain keeps its history.** Its configuration (headers, test users, scope, schedule) is deleted; its
  analyses, findings, triage and tickets stay as evidence and link back if the same host is added again.
- **Pages use the full width** and align with the header; the mobile layout of findings, repositories, the CVE tracker,
  analyses and the scope picker was redone.

### Fixed

- **"Affects you" in the latest CVEs** marked nearly every CVE: a package name matched anywhere in the description. It
  now needs the CVE to name your package as a product (followed by a version or "before/through/prior to").
- **Numbers and percentages follow the language** (Spanish "1.622", "0,2 %").
- **The view follows the address** when only its hash changes.
- **A web tool that exits 0 without reaching a host is no longer a clean result.** nuclei (now without `-silent`,
  with `-stats -sj`) skipping a host as unresponsive or refused ("denied address found for host"), templates that
  couldn't execute or statistics showing no request sent; katana whose seed only errored; httpx without an answer; and
  testssl.sh with a fatal `scanProblem` or an interrupted scan (exit 246) leave their step `partial`, name the hosts,
  add a limitation and report the tool `inconclusive` in `summary.tools`, so the registry doesn't mark that tool's
  earlier findings fixed.
- **katana found pitangus.dev's /es/ again.** With `-kf all`, katana 1.7 dropped links it also saw in robots.txt or a
  sitemap; the flag is gone (the inventory reads those files instead), and a URL its browser flags with an error after
  reading it stays in the crawl.
- **testssl.sh findings read as one problem each.** Rule ids lose their certificate suffix (`<hostCert#1>`, `<#2>`),
  a check repeated per certificate is one finding, and every certificate problem (chain of trust, revocation, the
  certificate's or an intermediate's expiry, lifetime, name) is one `certificate` finding per host with each check as
  evidence, merged with nuclei's certificate templates; `security_headers` folds into ZAP's header findings.
  **Changed:** testssl.sh findings get new fingerprints once (the old certificate ones are marked fixed by the next scan).
- **"Last run" in the page header is the newest analysis.** It took the first repository or image scan of the list, so
  newer web scans never showed; it now picks the newest analysis of any kind by date, and shows only on Overview,
  Findings and Analyses.

- **A scheduled scan is queued exactly once.** Locking the due domain, queuing its scan and moving its schedule on
  are now one transaction: a crash in between, or two rounds at once, can neither queue a slot twice nor lose it.

- **Web findings read as web findings.** Their location is the URL, never `URL:1`; the fix and re-verify texts say to
  deploy and scan the domain again instead of pushing to a branch; and their priority no longer asks to "confirm
  reachability" (a code concept) but says whether it comes from a response header, a cookie, an attack the scanner sent
  or is informational. Findings stored before get the new texts when read.

- **The same web alert on a site's root is one finding.** ZAP reports `https://host` and `https://host/` as different
  results; Pitangus already took both as the root, but counted them as two findings. A repeated alert on the same URL
  and parameter is now one (in code, the same rule twice on a line still counts twice). A later import of the same tool
  marks the leftover copy fixed.
- **Verifying a domain asks its own nameservers.** It went through the local resolver, which keeps a "no such name" for
  the zone's negative TTL (30 minutes on Cloudflare): a domain verified a little too early stayed "TXT not found" long
  after the record was published. It now asks the zone's authoritative nameservers first, and the local resolver only
  if they can't be reached.
- **The ZAP recipe in "Bring your own DAST" works as written.** Run with `--user "$(id -u)"`, ZAP couldn't create its
  home folder and stopped at once; it now runs as its own user over a writable folder, the image is pinned
  (2.17.0 by digest), and the import points at `zap.json`, the file the `sarif-json` template actually writes. Tried
  end to end against a real domain.
- **An organization batch now uses every worker.** The leader fed the batch one repository at a time, and only while
  the queue was empty, so with several workers a batch advanced at the pace of one. It now keeps as many of its
  repositories queued as there are workers with nothing waiting, also while the leader itself is scanning; scans
  launched by hand keep precedence.
- **A batch is "finished" when its last scan is.** With several workers, the batch was marked done, and its Slack or
  Teams notice sent, as soon as its last repository was queued, while the last scans were still running, so the notice
  could report fewer scans and findings than there were. It now waits for every scan of the batch to end.

### Security

- **The panel drops the `shadcn` package (292 fewer packages in its lockfile, braces among them).** Only its stylesheet
  was used; it is now copied into the panel, so the CLI and its tree (fast-glob, ts-morph, braces with
  GHSA-vfj7-8cjw-p6xm, which has no fixed release) are no longer installed to build it. The built panel doesn't change.
- **Checkov's `requirements.txt` no longer lists asteval 1.0.6.** The image already installed 1.0.10 over it
  (`overrides.txt`); the vulnerable pin stayed in the lock and scanners reported it. An overridden package now appears
  only in `overrides.txt`, and a test checks it.

## [0.12.2] - 2026-10-09

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

- **Slack and Teams notices read better.** No more emoji: each finding shows its severity in words and what it is,
  with where it is on the line below ("Dependency `next 14.2.3`" or the file and line), under "Most urgent". In Slack
  the edge of the message takes the colour of the most severe finding. Dependency advisories drop the repeated package
  prefix ("flatted 3.3.1: flatted: Flatted: Prototype pollution…" becomes "Prototype pollution…"); the signed webhook
  gets the same cleaner `title` and a new `dependency` flag per item.
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

### Upgrading from 0.12.1

- If you installed a release (`git clone --branch v0.12.1`, as in the quickstart), `make update` alone stays on it:
  `git fetch --tags && git checkout v0.12.2 && make update`. Following `main`, `make update` is enough. The new
  "Upgrade" section of [docs/installation.md](docs/installation.md#upgrade) explains both.
- The database gets one new table (the images added without scanning), created on start: nothing to do by hand.
- Slack and Teams notices change format (no emoji); a signed webhook receiver gets a cleaner `title` and a new
  `dependency` field per item.

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
