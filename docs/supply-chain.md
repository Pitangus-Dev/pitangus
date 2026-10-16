English · [Español](es/cadena-de-suministro.md)

# Supply chain

Pitangus runs third-party engines on your code, so the question "what exactly am I running?" has a precise answer: every engine and base image is pinned by digest, every release image is signed, and you can check that signature before you install. This page lists what is pinned, how it is checked and where in the repository each claim lives. It only states what the code at `main` does; what is not covered is at the end.

## Why it matters

A version tag is a pointer, and whoever holds the maintainer's credentials can move it. In March 2026 attackers did exactly that to the Trivy project's GitHub Actions: they repointed existing version tags of `aquasecurity/trivy-action` (76 of its 77 release tags, according to [CrowdStrike](https://www.crowdstrike.com/en-us/blog/from-scanner-to-stealer-inside-the-trivy-action-supply-chain-compromise)) to code that stole the secrets of every workflow that ran it, and `setup-trivy` was hit too ([Snyk](https://snyk.io/articles/trivy-github-actions-supply-chain-compromise/)). Workflows that asked for a tag ran the attacker's code without any change in their own repository; a full commit SHA or an image digest can't be moved that way. Both write-ups recommend pinning by commit SHA.

That is the mechanism Pitangus is built around: nothing it runs is named by a tag alone. No workflow in this repository uses either of those two actions.

## At a glance

| What | How it is pinned or checked | Where |
| --- | --- | --- |
| Engine images (Trivy, OSV-Scanner, Betterleaks, Grype, Checkov, zizmor and the web-scan engines) | By `sha256` digest | `IMAGES` in [`engines.py`](../pitangus/modules/scanning/engines.py), [`docker/app/Dockerfile`](../docker/app/Dockerfile) |
| Opengrep | Official binary checked against its SHA-256, on a base pinned by digest | [`docker/engines/opengrep/Dockerfile`](../docker/engines/opengrep/Dockerfile) |
| Base images, Caddy, PostgreSQL | By digest | Dockerfiles and compose files |
| Python packages | Hash-locked (`--require-hashes`) | `requirements.txt`, `docker/checkov/requirements.txt` |
| GitHub Actions used by this repository | Full commit SHA, with the version in a comment | [`.github/workflows/`](../.github/workflows/) |
| Release images | Built from a `v*` tag, SBOM and provenance attached, signed with cosign (keyless) | [`release.yml`](../.github/workflows/release.yml) |
| Release assets | SBOMs, provenance and a signed manifest of the image digests, attached to each GitHub release | [`release.yml`](../.github/workflows/release.yml), [`release-assets.sh`](../scripts/release-assets.sh) |
| Image used by the GitHub Action and the pre-commit hook | Signature checked, run by digest | [`action.yml`](../action.yml), [`hooks/pitangus-docker`](../hooks/pitangus-docker) |
| This repository's own practices | Scored by OpenSSF Scorecard, weekly | [`scorecard.yml`](../.github/workflows/scorecard.yml) |

## Engine images

Each engine runs from an image whose reference ends in `@sha256:…`. The single list is `IMAGES` in `pitangus/modules/scanning/engines.py`: Trivy, OSV-Scanner, Betterleaks, Grype, Checkov and zizmor, plus ZAP, subfinder, katana, nuclei, testssl.sh and httpx for web scans. A pulled image is always pulled by that digest, so a tag that moves on Docker Hub or GHCR changes nothing here.

The worker image with the engines inside (the one servers and the CI integrations use) copies the same binaries from the same digests: `FROM <image>@sha256:… AS trivy`, and so on, in `docker/app/Dockerfile`. `tests/test_packaging.py` fails if the two lists disagree, if any image in a compose file or Dockerfile has no digest, and if Checkov's lock or Opengrep's checksums differ between the app image and the engine image.

Two engines are not pulled from a registry:

- **Opengrep** is built from the project's official release binary, checked against the SHA-256 written in the Dockerfile (one per architecture). If it doesn't match, the image isn't built. `docker/engines/opengrep/VERIFY.md` shows how to repeat the upstream Cosign verification when upgrading.
- **Checkov** is installed from a hash-locked set of packages (`pip install --require-hashes`).

Other downloads in the build are checked the same way: the Docker CLI against its SHA-256, and nuclei's template archive at run time against a SHA-256 pinned in the code ([Security](security.md#what-leaves-your-machine)).

## How release images are built and signed

Pushing a `v*` tag runs [`release.yml`](../.github/workflows/release.yml), which publishes three images to GHCR:

| Image | Contents |
| --- | --- |
| `ghcr.io/pitangus-dev/pitangus:<version>` | Panel, API and worker |
| `ghcr.io/pitangus-dev/pitangus-worker:<version>` | Worker with the engines inside, no Docker socket needed |
| `ghcr.io/pitangus-dev/pitangus-opengrep:<engine version>` | The Opengrep engine |

What the workflow does, in order:

1. Refuses a tag that doesn't match `pitangus/version.py`.
2. Builds the image once for checking and runs Trivy on it, from the same image pinned by digest: **an image with a critical vulnerability that already has a fix is not published.**
3. Builds and pushes for `linux/amd64` and `linux/arm64` with `sbom: true` and `provenance: mode=max`: BuildKit attaches an SPDX SBOM and a SLSA provenance statement to the image.
4. Signs the image by digest, never by tag, with `cosign sign --recursive`: **keyless**, with the workflow's GitHub OIDC identity, so there is no signing key to store or leak. It then verifies its own signature before the job ends.

5. Attaches to the GitHub release of the tag the files described in [Release assets](#release-assets), in a job of its own.

The job that can write packages runs only from the `release` environment, with `contents: read`, `packages: write` and `id-token: write` and nothing else. The job that attaches the assets runs from the same environment with `contents: write` (to upload to the release) and `id-token: write` (to sign the manifest) and nothing else. `v*` tags are protected by a repository ruleset so they can't be moved or deleted (as the workflow's header notes), which is what makes the identity below meaningful.

The signature binds an image digest to this certificate identity, issued by GitHub's OIDC provider:

```
https://github.com/Pitangus-Dev/pitangus/.github/workflows/release.yml@refs/tags/v<major>.<minor>[.<patch>]
```

A build from a fork, from another workflow or from a branch has a different identity and fails the check.

## Release assets

From the first release built after this page was added, each [GitHub release](https://github.com/Pitangus-Dev/pitangus/releases) carries these files (`<version>` is the release's, such as `0.15.1`; releases before this change have none):

| File | What it is |
| --- | --- |
| `pitangus-<version>-images.json` | Manifest: the three images with their digest, each platform's digest and SBOM file name, the tag, the commit and the SHA-256 of every other file in the list |
| `pitangus-<version>-images.json.sigstore.json` | Cosign (keyless) signature of the manifest, with its certificate and transparency-log entry |
| `<image>-<version>-linux-amd64.spdx.json`, `…-linux-arm64.spdx.json` | The SPDX SBOM BuildKit attached to that platform's image, for each of the three images |
| `pitangus-<version>.intoto.jsonl` | The SLSA provenance of each image and platform, one in-toto statement per line, byte for byte as BuildKit stored it in the registry |

The `assets` job of `release.yml` runs after the images are built, signed and verified. It takes the signed digests from the previous job, checks their signatures again, reads the SBOMs and provenance of exactly those digests from the registry (`scripts/release-assets.sh`), signs the manifest and uploads everything with `gh release upload`. A maintainer creates the release by hand after pushing the tag, and the images take longer than that to build, so the job waits for the release (up to 15 minutes) and fails with a clear message if it never appears; it never creates the release. If it fails, create the release and re-run the job: the files are generated again.

The provenance file is not signed by itself (BuildKit's statements carry no signature); the signed manifest vouches for it through its SHA-256, and each statement names the digest of the image it is about. The SBOMs are what BuildKit saw while building: they list the packages of the image, not their vulnerabilities.

## Verify a release before you install it

You need [cosign](https://docs.sigstore.dev/cosign/system_config/installation/) and the Docker CLI.

```bash
# 1. The signature: it must come from the release workflow of a v* tag.
cosign verify \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github\.com/Pitangus-Dev/pitangus/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+(\.[0-9]+)?$' \
  ghcr.io/pitangus-dev/pitangus-worker:0.15
# The output's "docker-manifest-digest" is the exact image that was signed: use it (image@sha256:…) from here on.

# 2. The SBOM and the provenance attached to it.
docker buildx imagetools inspect ghcr.io/pitangus-dev/pitangus-worker:0.15 --format '{{json .SBOM}}'
docker buildx imagetools inspect ghcr.io/pitangus-dev/pitangus-worker:0.15 --format '{{json .Provenance}}'
```

To check the files attached to a release instead, download them from its page into one folder:

```bash
# 3. The manifest's signature: it must come from the release workflow of a v* tag.
V=0.15.1   # the release you downloaded
cosign verify-blob \
  --bundle pitangus-$V-images.json.sigstore.json \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github\.com/Pitangus-Dev/pitangus/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+(\.[0-9]+)?$' \
  pitangus-$V-images.json

# 4. The other files are the ones the manifest lists.
jq -r '.files | to_entries[] | "\(.value)  \(.key)"' pitangus-$V-images.json | shasum -a 256 -c -   # sha256sum -c on Linux
```

Each image digest in the manifest can be checked as in step 1, passing `ghcr.io/pitangus-dev/pitangus-worker@sha256:…` instead of the tag. To pin a release to its exact tag, use `--certificate-identity https://github.com/Pitangus-Dev/pitangus/.github/workflows/release.yml@refs/tags/v$V` instead of the regexp.

On a server, you don't need to run this by hand:

- `make setup PREBUILT=1` and `make up` run the same check (`make verify-images`) on the images of the version you checked out, refuse to start if it fails, and write the verified digest to `.env` (`PITANGUS_IMAGE_TAG=0.15@sha256:…`). Every later start, `docker compose up` included, runs exactly that image. `make update` checks and pins the new release. Without cosign, `make up` starts anyway and says the signatures weren't checked.
- Building from source instead (`make up` with no `PREBUILT`) needs no signature: the base images and engines are pinned by digest in the checkout you cloned, so check out a `v*` tag and read what you build.

## The GitHub Action and the pre-commit hook

Both run the published worker image, and both refuse to run an image Pitangus's release workflow didn't sign.

- **The GitHub Action** ([`action.yml`](../action.yml)) resolves the image (`ghcr.io/pitangus-dev/pitangus-worker:0.15` by default) to its digest, installs cosign with a pinned `sigstore/cosign-installer`, verifies that digest with the identity above and runs that same digest. A failed check ends the step with exit code 2. `verify: false` is rejected for the published image and exists only for an image of your own. To pin it yourself, pass an `image` that already carries a digest (`…pitangus-worker:0.15@sha256:…`); it's verified the same way. Pin the Action itself to the commit of a release tag, as the examples in [Terminal and CI](cli.md) say.
- **The pre-commit hook** ([`hooks/pitangus-docker`](../hooks/pitangus-docker)) has the image written in as `…pitangus-worker:0.15@sha256:…`, never a bare tag. `make pin-hook` rewrites that digest after each release, after checking the signature with the same command. With cosign installed, the hook verifies the signature again before each run and exits with code 2 if it fails; without it, the hook says so and runs.

## This repository's own pipeline

- **Third-party actions are pinned by commit SHA**, with the version in a comment (`# v7.0.1`). `tests/test_packaging.py` and `tests/test_action.py` fail the build if any `uses:` in a workflow or in `action.yml` is not a 40-character SHA (the only exception is `./`, the CI job that tests the Action itself).
- **Least privilege.** Every workflow starts with `permissions: {}` (a test enforces it) and each job asks only for what it needs. Every checkout uses `persist-credentials: false`, and in shell steps values from events reach the script through `env:`, never interpolated into the command (`tests/test_action.py` checks it).
- **Pitangus scans itself.** The CI job "Pitangus on itself" runs the product's own engines on every pull request, zizmor included on the workflows, and blocks what the change introduces from high severity up.
- **OpenSSF Scorecard** ([`scorecard.yml`](../.github/workflows/scorecard.yml)) scores the repository on pinned dependencies, token permissions, branch and tag protection, dependency updates and more, on every push to `main`, weekly and when branch protection changes. The result is public, in the badge on the README and in the [Scorecard viewer](https://scorecard.dev/viewer/?uri=github.com/Pitangus-Dev/pitangus), and the findings go to code scanning. It reads the repository; it changes nothing.

## How updates are reviewed

- **Dependabot** ([`dependabot.yml`](../.github/dependabot.yml)) proposes weekly, grouped updates for GitHub Actions, base images, Python and npm packages, and ignores releases younger than 7 days (`cooldown`): a hijacked release is usually caught and pulled within days. Security updates skip the wait.
- **The panel and the docs site** install with pnpm and `pnpm-workspace.yaml` settings that refuse versions younger than a week (`minimumReleaseAge`), refuse a version that loses the provenance its predecessors had, block dependencies from git or tarball URLs and never run dependencies' build scripts. A fix younger than a week goes in as an exception for one exact version (`minimumReleaseAgeExclude`), with the advisory and the date it stops mattering. See [Development](development.md).
- **Engine images are updated by hand**, in a pull request that changes the digest in `IMAGES` and in the Dockerfile together; Dependabot is told to leave them alone so the two can't drift, and the packaging test fails if they do. There is no automatic age rule for them: the review is the pull request, CI (including the self-scan) and the release gate described above. A repository ruleset on `main` requires pull requests and passing status checks (a repository setting, so it isn't in the code).

## What this doesn't give you

- A valid signature says the image was built by Pitangus's release workflow from a `v*` tag of this repository. It doesn't say the code has no bugs. Pinning keeps an engine from changing under you; it doesn't make the engine's own code trustworthy, which is why engines run with no capabilities, a read-only filesystem and, where the platform allows, no network ([Security](security.md#code-analysis)).
- The builds aren't reproducible bit for bit, and the provenance is BuildKit's own statement, not a claimed SLSA level. The attached `.intoto.jsonl` is that statement unchanged, not a signed attestation from a SLSA generator.
- On a laptop the worker still uses the Docker socket, which is equivalent to root on the host ([known trade-offs](security.md#known-trade-offs)).
- A Scorecard score is a heuristic over repository settings. It's evidence, not a guarantee.

To report a vulnerability in any of this, see [SECURITY.md](../.github/SECURITY.md).
