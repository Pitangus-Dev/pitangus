English · [Español](es/README.md)

# Documentation

| Document | What it covers |
| --- | --- |
| [What is Pitangus](overview.md) | What it does and for whom, what it covers and what it doesn't, a tour of the panel and its shortcuts. |
| [Quickstart](quickstart.md) | From zero to your first fixed finding, with demo data, and what to set up next. |
| [Key concepts](concepts.md) | Analysis and pentests, assets, runs and steps, findings and fingerprints, lifecycle, triage, roles and workers. |
| [Installation](installation.md) | Requirements, first start, upgrades, backups and uninstalling. |
| [Where to deploy](deploy.md) | Every target: one-file compose (Coolify, Dokploy, Portainer, Hostinger), Render, Railway, Vercel for the API, Kubernetes, and the periodic tasks. |
| [Deploy on a VPS](deploy-vps.md) | Your own server with a domain: sizing, OS prep, HTTPS with Caddy, published images, backups and restore, upgrades, monitoring, Coolify and Dokploy. |
| [Scaling](scaling.md) | What one worker does, adding workers on one machine or several, scanning in CI instead, sizing, and what doesn't scale yet. |
| [Containers and Makefile](containers.md) | What you need, every `make` command, the images, the `docker/` layout and hardening. |
| [Connect GitHub](github-app.md) | Create your GitHub App step by step, install it and review pull requests. |
| [Integrations and automation](integrations.md) | GitHub, CI and SARIF, Jira, notifications, webhooks and periodic tasks. |
| [Configuration](configuration.md) | Every `.env` variable. |
| [Security](security.md) | How secrets are stored, what leaves your machine and known trade-offs. |
| [Scan your code](scanning-code.md) | Code, dependencies, secrets, infrastructure and pipelines; pull request review and the engines. |
| [Scan container images](scanning-images.md) | Images read from the registry, never run: packages, secrets and configuration. |
| [Scan a website or API](scanning-web.md) | Passive web and API scans of a verified domain: scope, headers, test users and schedules. |
| [Findings](findings.md) | The registry, triage, deadlines, verification, the CVE tracker and exports. |
| [Compliance](compliance.md) | SBOM, VEX, malicious packages, audit evidence and the CRA kit. |
| [Threat modeling](threat-modeling.md) | Models, approaches (STRIDE, LINDDUN, PASTA, attack trees, ATT&CK) and evidence from scans. |
| [Upgrade](upgrading.md) | The upgrade procedure, and what changes when you move to 0.15. |
| [Architecture](architecture.md) | Components, how a scan flows and what is stored on disk. |
| [Troubleshooting](troubleshooting.md) | Common errors and how to fix them. |
| [FAQ](faq.md) | Short, honest answers to common questions. |
| [Glossary](glossary.md) | Every application security term used in these pages. |
| [Development](development.md) | Running without containers, the CLI, tests and bilingual text. |
| [Brand](brand.md) | Pitangus's name, mascot, logo, colors and voice. |
| [Third-party software](third-party-notices.md) | Licenses of the engines, advisory databases and dependencies. |
