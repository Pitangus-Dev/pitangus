# Pitangus documentation site

This directory contains the Astro Starlight application that turns the repository's existing English and Spanish documentation into a searchable static site.

## Run it locally

Use Node.js 22.12 or newer and pnpm through corepack (`corepack enable`; `package.json` pins the version):

```bash
cd docs-site
pnpm install --frozen-lockfile
pnpm run dev       # http://localhost:4321
pnpm run check     # source consistency and Astro type checks
pnpm run build     # production build and internal-link validation
pnpm run preview   # http://localhost:4322 after a build
```

The default local base path is `/`. To test the production URL exactly:

```bash
SITE_URL=https://docs.pitangus.dev BASE_PATH=/ pnpm run build
SITE_URL=https://docs.pitangus.dev BASE_PATH=/ pnpm run preview
```

On PowerShell:

```powershell
$env:SITE_URL = 'https://docs.pitangus.dev'
$env:BASE_PATH = '/'
pnpm run build
pnpm run preview
```

## Canonical content

Do not edit `src/content/docs/`. It is generated and ignored by Git.

- English documentation stays in `../docs/*.md`.
- Spanish documentation stays in `../docs/es/*.md`.
- Contributor guides stay in `../.github/CONTRIBUTING*.md`.
- The Starlight home pages live in `content/` because they use MDX components and site-specific frontmatter.
- `scripts/sync-content.mjs` gives translated pages matching slugs, adds metadata and edit links, rewrites repository links, and copies documentation assets, the logo, and the favicon.

Every `dev`, `check`, and `build` command runs the sync first. When adding an English document, add its Spanish counterpart and update the filename map, metadata, and sidebar.

## Generated API reference

`scripts/sync-content.mjs` reads `../web/src/shared/api/openapi.json` and generates the automation API reference. It includes only routes explicitly intended for unauthenticated health checks or token-authenticated operation: health, Prometheus metrics, external periodic tasks, and CI SARIF import. Session routes used by the panel are intentionally excluded because they are not a stable public API.

After changing a FastAPI route, run this from the repository root before building the site:

```bash
make openapi
```

The complete schema is used only as a build input and is not copied into the public site because it also describes the panel's internal session routes. FastAPI does not serve that schema or interactive API documentation at runtime.

## Deployment decision

The public landing remains an independent deployment at `https://pitangus.dev/`. Documentation uses the dedicated `https://docs.pitangus.dev/` subdomain so neither deployment needs to own a path in the other's artifact.

`.github/workflows/docs.yml` validates the site on pull requests and pushes, while publication remains manual through `workflow_dispatch`. To activate the custom domain:

1. In this repository, select **Settings → Pages → GitHub Actions** and set the custom domain to `docs.pitangus.dev`.
2. In Cloudflare DNS, create a `CNAME` record named `docs` pointing to `pitangus-dev.github.io`. Start with the record set to **DNS only** while GitHub validates the domain and provisions HTTPS.
3. Run the **Documentation** workflow manually and enable **Enforce HTTPS** when GitHub makes the option available.
4. Update the landing's **Read the docs** link to `https://docs.pitangus.dev/` in its own repository.

GitHub Actions deployments do not require a checked-in `CNAME` file; the custom domain is stored in the repository's Pages settings.
