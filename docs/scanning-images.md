English · [Español](es/analisis-de-imagenes.md)

# Scan container images

An image scan reads a container image straight from its registry and tells you what it carries before you deploy
it: packages with known vulnerabilities, secrets left in its layers or its build history, and risky settings such as
running as root. **The image is never run or built**, and it takes no space in your Docker. As with every scan, the
results are findings to confirm, and a clean result doesn't prove there are no vulnerabilities. Terms are explained
in the [glossary](glossary.md).

## Prerequisites

- Pitangus running ([installation](installation.md)), with the engine images available (`make up` or
  `make engines`): Trivy, Grype and Checkov.
- The image reference, exactly as you'd use it in `docker pull`: `ghcr.io/acme/api:1.4`, `nginx:1.27` (Docker Hub
  images can go without the registry) or `…@sha256:…`. Pin a version or a digest so you know exactly what you
  reviewed; without a tag, `latest` is assumed.
- For a private image: a **read-only** token for its registry, saved by an administrator (see
  [Private registries](#private-registries)). Public images need nothing.

## Scan an image from the panel

1. Click **New scan** (or press `N`) and choose **Container image**.
2. In **Images**, write one reference per line. Up to 100 per batch; several images run one after another, and you
   can follow them in **Scans**. Under the field, each registry says whether saved credentials will be used or
   access is public. If you just want to try it, the panel offers public examples (an old image with many
   advisories, a recent one with few, and one vulnerable on purpose).
3. Optionally add **Context** for the report, then **Review and launch**.

The scan runs in the background like any other ([Background scans and progress](scanning-code.md#background-scans-and-progress)).

## Scan an image from the terminal

`scan-image` is useful in CI, after you build and push an image. It runs inside the Pitangus API container, so the
server must be up, and the result is saved and shows up in the panel:

```bash
make cli ARGS="scan-image --reference ghcr.io/acme/api:1.4"
```

It prints a JSON summary. The shape is this (the values are an example):

```json
{
  "id": "…",
  "status": "completed",
  "image": "ghcr.io/acme/api:1.4",
  "summary": {
    "candidates": 42,
    "severities": {"critical": 1, "high": 9, "medium": 20, "low": 12},
    "agreement": 30,
    "kev": 1
  }
}
```

`agreement` counts the advisories both Trivy and Grype reported; `kev` the ones in the CISA KEV catalog.

| Exit code | Meaning |
| --- | --- |
| `0` | No findings |
| `1` | There are findings |
| `2` | Invalid input: the reference isn't valid, the registry doesn't resolve or resolves to a private address |
| `3` | Incomplete: an engine didn't run, so the result proves nothing |

These are the same codes as `scan-repository` and [`scan`](cli.md).

## What is checked

| What | How |
| --- | --- |
| System and application packages | **Trivy 0.75.0 and Grype 0.120.0.** On source code they agree almost completely; on images they disagree on packages whose fixes the distribution backported (on `nginx:1.21`: 781 advisories in common, 99 only from Trivy and 11 only from Grype, one of them critical). Advisories are merged by package, version and identifier (CVE or GHSA); those both engines see get a confidence boost. |
| Secrets in layers | Trivy looks for credentials in each layer's files. |
| Credentials in `ENV` | Variables with a secret-like name (`*_TOKEN`, `*_PASSWORD`, `API_KEY`…) and a hard-coded value: anyone who pulls the image reads them with `docker inspect`. |
| Credentials in the build history | `ARG`s used in a `RUN` (for example `NPM_TOKEN=… npm ci`), URLs with a username and password, and hard-coded `Authorization` headers: they stay in the image and `docker history` shows them. The recommended fix is BuildKit's `RUN --mount=type=secret`. |
| Configuration | Pitangus rules: root user, missing `HEALTHCHECK`, `ADD` from a URL, exposed SSH, the `latest` tag without a digest, and images more than a year old. |
| History instructions | **Checkov** on a Dockerfile rebuilt from the image's history: downloads with TLS checks disabled (`curl -k`, `wget --no-check-certificate`, `NODE_TLS_REJECT_UNAUTHORIZED=0`), `pip --trusted-host`, unsigned package managers, `sudo`, `chpasswd`… Each finding points to the history step. The Dockerfile is rebuilt because Checkov's own image mode requires a Prisma Cloud account. |

Configuration findings that Trivy, Checkov and the Pitangus rules all see stay one finding (the Pitangus rule is the
primary one). Dependency advisories get the same treatment as in a code scan: fixed version, KEV, EPSS and priority
([Dependency findings](scanning-code.md#dependency-findings)).

No secret value is stored: only the variable's name or the history step.

## Private registries

An administrator saves the credentials in **Integrations → Container registries** (**Add registry**). They're
encrypted on the server, never sent back to the browser and never written to the logs; they reach the engines through
environment variables, not the command line. Saving again for the same registry replaces them. Always use a
**read-only** token:

| Registry (host) | Username | Token |
| --- | --- | --- |
| `ghcr.io` | your GitHub username | classic token with only `read:packages` |
| `docker.io` | your Docker Hub username | read-only access token (Account settings, Personal access tokens) |
| `<account>.dkr.ecr.<region>.amazonaws.com` | `AWS` | output of `aws ecr get-login-password` (expires after 12 h) |
| `<region>-docker.pkg.dev` | `_json_key_base64` | key of a service account with Artifact Registry Reader |

Registries on your internal network (private IP addresses) are blocked, so nobody can use the panel to make the
server reach internal services. To scan from your own registry on the local network, start the server with
`PITANGUS_ALLOW_PRIVATE_REGISTRIES=1` ([Configuration](configuration.md)).

## What you'll see in the panel

Each image is its own asset in **Findings**, identified by registry and repository, **without the tag**. When you
scan `api:1.5`, whatever no longer appears compared with `api:1.4` is marked fixed, and whatever comes back is
reopened. The run's header shows the digest and how many advisories both engines confirmed.

**Images** lists the images you've scanned (or added) and the repository each one is built from:

- **The link to its repository.** Pitangus reads it from the image's OCI labels
  (`org.opencontainers.image.source` and `org.opencontainers.image.revision`). When they're missing or wrong, an
  administrator links it by hand (**Link a repository**), and the manual link wins over the label.
- **What the link gives you.** A repository's evidence brings the images built from it, reports say "built from
  org/repo @ commit", and the scope picker in Findings and Compliance can include them with the repository
  ([Several assets at once](findings.md#several-assets-at-once)).
- **Add image** puts an image on the list without scanning it, optionally linked to its repository (**Built from**)
  and scanned right away if you tick **Scan it now**. It joins findings and evidence with its first scan. An
  administrator can remove an image that was never scanned.

## What it doesn't cover

An image scan reads the packages and the configuration inside the image. How the application behaves needs a scan
of its code and of the deployed site. Operating system packages are checked for new advisories only when the image
is scanned again (the daily advisory watch covers code dependencies).

## Common errors

| What you see | Why | What to do |
| --- | --- | --- |
| "Invalid image reference: use registry/repository:tag" | The reference isn't in `docker pull` form (uppercase, spaces…) | Write it as `registry/repository:tag`, in lowercase. |
| "Couldn't resolve the registry …" | The registry's name doesn't resolve from the server | Check the name and the server's DNS. |
| "The registry … resolves to a private address" | Internal registries are blocked by default | Start the server with `PITANGUS_ALLOW_PRIVATE_REGISTRIES=1` if it's yours. |
| The scan fails with an authentication error | No credentials, or the token expired (ECR tokens last 12 h) | Save or renew the token in **Integrations → Container registries**. |
| Exit code `3` or an incomplete run | An engine didn't run | Run `make engines` and check the run's steps. |

More in [Troubleshooting](troubleshooting.md).

## Next steps

- [Findings, triage and remediation](findings.md).
- [Compliance evidence](compliance.md): SBOM and VEX for images and the repositories they're built from.
- [Scan your code and dependencies](scanning-code.md).
- [Scanning from the terminal and in CI](cli.md).
