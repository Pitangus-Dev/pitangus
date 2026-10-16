English · [Español](SECURITY.es.md)

# Security policy

Pitangus reads your repositories' code and stores credentials, so we take reports seriously. This page says how to report a vulnerability, what we support and what to expect. How the product protects your data is in [docs/security.md](../docs/security.md); how releases are built, signed and verified is in [docs/supply-chain.md](../docs/supply-chain.md).

## Reporting a vulnerability

**Don't open a public issue, pull request or discussion.** Report it privately with GitHub's private vulnerability reporting: [open a draft security advisory](https://github.com/Pitangus-Dev/pitangus/security/advisories/new) (the **Security → Report a vulnerability** tab of this repository). Only the maintainers and the people you add can see it.

If you can, include:

- the version (`/api/health` or the label in the panel) and how you deploy it;
- the affected part (file, route or component) and what an attacker needs to start from (no account, a member, an administrator);
- steps to reproduce it, ideally a proof of concept, and the impact you see;
- whether it's already public or being exploited.

Don't include real secrets, yours or anyone else's, and test only against an instance you own: don't read, change or delete other people's data, and don't run denial-of-service tests against servers that aren't yours.

## What to expect

Pitangus is maintained by a small team, so these are targets, not guarantees:

- **Acknowledgement** within 5 business days.
- **First assessment** (whether we can reproduce it and how serious we think it is) within 10 business days. We'll tell you if we disagree that it's a vulnerability, and why.
- **Fix:** for a confirmed high or critical issue, a patch release as soon as it's ready and tested, aiming at 30 days from the report; lower severities go into the next regular release. If it will take longer, we'll tell you why and keep you posted.
- Issues that expose credentials or let someone run code on a server go first.

## Coordinated disclosure

Please keep the details private until a fixed version is out. When it is, we publish a GitHub security advisory describing the affected versions, the fix and the upgrade path, and we ask for a CVE through GitHub when the issue warrants one. We credit you in the advisory unless you'd rather not be named. We'd like to publish within 90 days of the report; if a fix needs longer, we'll agree a date with you instead of letting it lapse. The fix is listed in the [changelog](../CHANGELOG.md).

## Supported versions

Pitangus is in beta (0.x). Security fixes go into **the latest minor release line (currently 0.15.x)**, as a patch release (for example 0.15.1), and into the `main` branch. Earlier lines are not patched: [upgrade](../docs/upgrading.md) to the latest one. Releases are listed on the [Releases page](https://github.com/Pitangus-Dev/pitangus/releases).

## Scope

In scope: any flaw in the code of this repository or in the artifacts it publishes: authentication, sessions, the secret store, the API, the panel, how engines are run, the images on `ghcr.io/pitangus-dev` and the release workflow that builds and signs them.

Out of scope:

- **Deliberately vulnerable samples:** the code in `fixtures/` and `tests/fixtures/` (the examples engines are tested against) and the demo data built from them. Their flaws are there on purpose.
- **Third-party tools** Pitangus runs (Trivy, OSV-Scanner, Betterleaks, Opengrep, Grype, Checkov, zizmor, ZAP, nuclei and the rest): report them to their projects. A way to make Pitangus run one unsafely is in scope.
- **Documented trade-offs**, such as using the Docker socket on a laptop ([known trade-offs](../docs/security.md#known-trade-offs)), and settings you chose to weaken (for example `PITANGUS_ALLOW_INSECURE_HTTP=1`).
- Findings that need access an attacker already has: root on the host, a stolen master key or an administrator's credentials.
- Reports from automated scanners with no demonstrated impact, missing best-practice headers with no exploit, and social engineering or physical attacks.

If you're not sure whether something is in scope, report it privately anyway.
