English · [Español](es/inicio-rapido.md)

# Quickstart: from zero to a verified fix

This guide takes you from nothing to Pitangus running on your machine, a scan of real vulnerable code, and a fix
Pitangus confirms, in about 15 minutes. You don't need to know application security: each step says what you'll see.
Steps marked **optional** can wait. New to the terms? See [What is Pitangus](overview.md) and the
[glossary](glossary.md).

## Prerequisites

- **Docker** (Engine 24 or later with Compose v2.24 or later), **make** and **git**.
- 4 GB of memory and 8 GB of free disk.
- macOS, Linux, or Windows with WSL2 (clone inside Linux, not under `/mnt/c`).

## 1. Start it (5 min)

```bash
git clone --branch v0.15.0 https://github.com/Pitangus-Dev/pitangus.git
cd pitangus
make doctor
```

`make doctor` checks Docker, Compose, disk, the port and permissions. Every line should start with `✓`:

```text
Result: 14 passed, 0 warnings, 0 errors
```

A `✗` line says what to fix on the line below it. Then:

```bash
make setup PREBUILT=1
make up
```

`make setup PREBUILT=1` creates `.env` and the folders and chooses the published, signed images instead of building
them (leave it out to build from the code). `make up` pulls them and the engines, about 800 MB: under a minute on a
fast connection, some 2 minutes at 50 Mbps (measured from scratch: about 1 minute at 150 Mbps, 3 on a laptop with WSL2).
Behind a corporate VPN or proxy the first download can take much longer: see [Troubleshooting](troubleshooting.md).
It ends like this:

```text
Waiting for the panel to respond.....
Engines: ready.
Panel: http://127.0.0.1:8766
Setup code: …
```

Open <http://127.0.0.1:8766> and create the administrator account with the **setup code**. If you lose it,
`make setup-code` prints it again.

Right after that the panel asks you to turn on two-factor authentication (TOTP) with your authenticator app: it's
mandatory for administrators (`PITANGUS_REQUIRE_TOTP`, see [Configuration](configuration.md)), and nothing else opens
until it's on. Save the backup codes it shows you.

The panel follows your browser's language; switch it any time from the header or the sign-in screen. PR comments,
notifications, Jira, reports and CLI output use `PITANGUS_DEFAULT_LOCALE` (`en` by default).

## 2. See it work without connecting anything (2 min)

```bash
make demo
```

It runs a real scan, with the same engines as the panel, over the intentionally vulnerable examples shipped with the
repository (code in seven languages, dependencies with known vulnerabilities, a secret and a Dockerfile), and imports a
sample threat model:

```text
Analyzing … example files with Pitangus's engines…
Code: … findings (completed).
Example threat model imported: "Demo · Customer portal (STRIDE)".
Done: open the panel and look at Overview, Findings and Threats.
```

In the panel you'll see the **demo · vulnerable samples** asset:

- **Overview:** findings by severity, actively exploited vulnerabilities (KEV), and what to handle first.
- **Findings:** expand one and look at **How to fix it** (the command or the code example).
- **Threats:** the diagram, the threats and the PDF report.

<!-- screenshot: overview | The Overview dashboard after make demo, with findings by severity and the Getting started checklist -->

`make demo IMAGE=nginx:1.21` also scans a public container image (Trivy, and Grype too if you turned it on; a couple
of minutes).

`make demo FULL=1` also builds **Lapis Labs**, a made-up organization that fills every view, offline and in seconds:
five `lapis-labs/…` repositories with a month of scans (trends, fixed findings, MTTR, due dates, some overdue), a pull
request review, a container image, the domain `tienda.example.com` verified for the demo (scope, a weekly schedule,
a test user, detected technologies and two passive web scans), `soporte.example.net` pending, two members marked
"(demo)" and a few triage decisions,
signed by `demo` or those members, never by you. Its findings are engine outputs recorded against these same samples
(`tests/fixtures`, `tests/engine-outputs`), replayed through the normal parsers and registry: nothing is scanned or
contacted. Create the admin account first (the members wait for it), and open the Overview once before running it if
you want KEV and EPSS on the findings (it downloads those feeds; the demo only reads them). The demo domains, under
names reserved for examples, are never verified or scanned for real. Running it again adds nothing. Slack and Jira
are left out: saving them contacts their servers.

> [!WARNING]
> `FULL=1` writes into the workspace you run it on, next to your real data, and nothing removes it afterwards. Use it
> on an install for trying Pitangus or taking screenshots, not on the one your team works in.

## 3. Connect your GitHub repositories (5 min)

Under **Integrations → Code providers**, the panel walks you through creating your server's GitHub App with only the
permissions it needs (read code, comment and set statuses on PRs). At the end you install it on the repositories you
want: *Only select repositories* is a good way to start. Details in [Connect GitHub](github-app.md).

Not on GitHub (GitLab, Bitbucket, Azure DevOps or a local folder)? Use [`scan` in the terminal or in CI](cli.md).

## 4. First scan and first fix

1. Click **New scan** in the header (or press `N`). The guided flow has a step rail on the side: pick **Code**, then
   **Add repositories** and choose one or more (or **Whole organization**). Optionally add **Context** for the report,
   then check **Review and launch** and click **Start scan**.
2. The scan runs in the background; follow it in **Scans**. When it finishes, the panel shows a notice.
3. In **Findings**, start with anything marked KEV or critical. Each finding's **How to fix it** has what the tool knows: a command, an example to adapt or the scanner's own advice.
4. Apply the fix, push it to the main branch and click **Reverify** on the finding. When the scan finishes, it says
   **Fixed ✓ · no longer found in the scan** or **Still present in the scan**. If the scan was incomplete, it says so,
   because an incomplete scan proves nothing.

<!-- screenshot: new-scan | The New scan guided flow on its first step, with the Code, Container image and Web app or API types -->

If you decide not to fix something, record it in triage (accepted risk or false positive) with a reason, and for an
accepted risk an expiry date: it stays as evidence and stops getting in your way. See [Findings](findings.md).

## 5. Let it run on its own (optional, recommended)

- **Pull requests and main branch:** in **Pull requests**, an administrator turns on watching for your repositories.
  Every PR is reviewed automatically (only what it introduces counts) and the main branch is rescanned after each
  merge. See [Scan your code](scanning-code.md).
- **Daily new-advisory check:** on by default. Once a day your dependencies are checked, offline, against the
  advisories published since the last scan.
- **Notifications in your channel:** under **Integrations → Notifications**, an administrator adds Slack, Teams or a
  webhook so you hear about things without opening the panel. For messages to link to the finding, set
  `PITANGUS_PUBLIC_URL`.

## 6. Check your website's exposure (optional)

If you run a website or an API, Pitangus can check what it shows anyone, with nothing to turn on: exposed files such
as `.git` or `.env`, debug and status consoles, weak TLS and missing security headers. As an administrator: **Domains & APIs → Add
domain**, prove you control it (a DNS TXT record, a file or a meta tag), and launch **New scan → Exposure check**. It
only requests each host's root and a list of known paths: it doesn't crawl the site and it never attacks.

The **full web scan**, which crawls the site with ZAP, katana and subfinder like a visitor would (cookie flags,
outdated libraries, every page and API endpoint, test users and schedules), is experimental and off until the server
sets `PITANGUS_DAST_ENABLED=1`:

```bash
echo 'PITANGUS_DAST_ENABLED=1' >> .env
make up
```

Then it's under **New scan → Full web scan**. The full walkthrough is in [Scan a website or API](scanning-web.md).

## 7. Later on (optional)

- **Team:** invite more people under **Users** (member or administrator role).
- **Jira:** under **Integrations → Issue tracking**, to turn findings into issues without duplicates.
- **Private images:** read-only credentials under **Integrations → Container registries**. See
  [Scan container images](scanning-images.md).
- **Audits:** in **Findings**, **More formats → Audit evidence (SOC 2, ISO, PCI…)…** generates the PDF (or **Report on
  selected** for the ones you tick). See [Compliance](compliance.md).
- **Upgrades:** you installed a fixed version, so `make update` alone stays on it. When a new one comes out
  ([Releases](https://github.com/Pitangus-Dev/pitangus/releases)), see [Upgrade Pitangus](upgrading.md).
- **From another machine:** put it behind HTTPS ([Deploy on a VPS](deploy-vps.md)); outside `127.0.0.1` it won't start
  without HTTPS.

## If something goes wrong

| Symptom | Fix |
| --- | --- |
| `make doctor` shows a `✗` | Do what the line below it says, then run `make doctor` again. |
| The first `make up` is very slow | You're probably behind a VPN or proxy: see [Troubleshooting](troubleshooting.md#vpn-and-proxy). |
| You lost the setup code | `make setup-code`. |
| An engine shows as *Not tested* | `make status` lists missing images; `make engines` pulls them. |

More in [Troubleshooting](troubleshooting.md).

## Next steps

- [Key concepts](concepts.md): runs, findings, fingerprints and triage.
- [Scan your code](scanning-code.md), [Scan container images](scanning-images.md),
  [Scan a website or API](scanning-web.md).
- [Integrations and automation](integrations.md): CI, SARIF, Jira and notifications.
