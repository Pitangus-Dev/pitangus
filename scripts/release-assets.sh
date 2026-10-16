#!/bin/sh
# The files attached to a GitHub release, read from the images already published (release.yml runs this after they are
# built, signed and verified; nothing is built or pushed here, and nothing is signed: release.yml signs the manifest).
#
#   sh scripts/release-assets.sh OUT_DIR VERSION IMAGE@sha256:INDEX_DIGEST...
#
# Per release, in OUT_DIR:
#   <image>-<version>-<os>-<arch>.spdx.json   the SPDX SBOM BuildKit attached to that platform's image
#   pitangus-<version>.intoto.jsonl           its SLSA provenance, one in-toto statement per line, byte for byte as
#                                              BuildKit stored it in the registry (unsigned: the manifest vouches for it)
#   pitangus-<version>-images.json            every image with its digest, its platforms and the SHA-256 of each file
# Needs docker (buildx), curl and jq; the images must be readable without credentials (GHCR packages are public).
# Optional environment, written into the manifest: RELEASE_TAG, RELEASE_REPOSITORY, RELEASE_COMMIT, RELEASE_IDENTITY.
set -eu

[ "$#" -ge 3 ] || { echo "usage: $0 OUT_DIR VERSION IMAGE@sha256:DIGEST..." >&2; exit 2; }
out=$1 version=$2
shift 2
mkdir -p "$out"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
tab=$(printf '\t')

sha256() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }
fail() { echo "::error::$*" >&2; exit 1; }

provenance="$out/pitangus-$version.intoto.jsonl"
: > "$provenance"
images='[]'
files='{}'

for ref in "$@"; do
  case $ref in *@sha256:*) ;; *) fail "$ref has no digest: the assets of a release are read by digest, never by tag." ;; esac
  name=${ref%@*} digest=${ref#*@}
  image=${name##*/} host=${name%%/*} repo=${name#*/}

  docker buildx imagetools inspect --raw "$ref" > "$work/index.json"
  docker buildx imagetools inspect "$ref" --format '{{json .SBOM}}' > "$work/sboms.json"
  curl -fsS "https://$host/token?service=$host&scope=repository:$repo:pull" | jq -r .token > "$work/token"
  registry() { curl -fsSL --retry 3 -H "Authorization: Bearer $(cat "$work/token")" -H 'Accept: application/vnd.oci.image.manifest.v1+json' "https://$host/v2/$repo/$1/$2"; }

  # One line per platform image: platform, its manifest digest and its attestation manifest's digest.
  jq -r '
    (.manifests | map(select(.annotations["vnd.docker.reference.type"] == "attestation-manifest")
                      | {key: .annotations["vnd.docker.reference.digest"], value: .digest}) | from_entries) as $att
    | .manifests[] | select(.annotations["vnd.docker.reference.type"] == null)
    | [([.platform.os, .platform.architecture, .platform.variant] | map(select(. != null)) | join("/")), .digest,
       ($att[.digest] // error("no attestation for " + .digest))]
    | @tsv' "$work/index.json" > "$work/platforms.tsv"
  [ -s "$work/platforms.tsv" ] || fail "$name has no platform images."

  platforms='[]'
  while IFS=$tab read -r platform manifest attestation; do
    file="$image-$version-$(printf '%s' "$platform" | tr / -).spdx.json"
    jq --arg p "$platform" '.[$p].SPDX // error("no SBOM for " + $p)' "$work/sboms.json" > "$out/$file"

    # The attestation manifest lists in-toto statements as blobs; keep the provenance one exactly as stored.
    registry manifests "$attestation" > "$work/attestation.json"
    blob=$(jq -r '[.layers[] | select(.annotations["in-toto.io/predicate-type"] | startswith("https://slsa.dev/provenance/"))] |
                  if length == 1 then .[0].digest else error("expected one provenance statement") end' "$work/attestation.json")
    registry blobs "$blob" > "$work/statement"
    [ "sha256:$(sha256 "$work/statement")" = "$blob" ] || fail "The provenance of $image ($platform) does not match its digest in the registry."
    [ "$(wc -l < "$work/statement" | tr -d ' ')" -le 1 ] &&
      jq -e --arg d "${manifest#sha256:}" '.subject | map(.digest.sha256) | index($d) != null' "$work/statement" > /dev/null ||
      fail "The provenance of $image ($platform) is not one statement about this image."
    cat "$work/statement" >> "$provenance"
    [ -z "$(tail -c1 "$work/statement")" ] || echo >> "$provenance"

    files=$(printf '%s' "$files" | jq -c --arg f "$file" --arg h "$(sha256 "$out/$file")" '. + {($f): $h}')
    platforms=$(printf '%s' "$platforms" | jq -c --arg p "$platform" --arg d "$manifest" --arg f "$file" '. + [{platform: $p, digest: $d, sbom: $f}]')
  done < "$work/platforms.tsv"

  images=$(printf '%s' "$images" | jq -c --arg n "$name" --arg d "$digest" --argjson p "$platforms" '. + [{name: $n, digest: $d, platforms: $p}]')
done

[ -s "$provenance" ] || fail "No provenance found."
files=$(printf '%s' "$files" | jq -c --arg f "$(basename "$provenance")" --arg h "$(sha256 "$provenance")" '. + {($f): $h}')

jq -n --arg version "$version" --arg tag "${RELEASE_TAG:-v$version}" --arg repository "${RELEASE_REPOSITORY:-}" \
  --arg commit "${RELEASE_COMMIT:-}" --arg identity "${RELEASE_IDENTITY:-}" \
  --argjson images "$images" --argjson files "$files" '
  {version: $version, tag: $tag, repository: $repository, commit: $commit, signer: $identity,
   images: ($images | sort_by(.name)), files: $files}
  | with_entries(select(.value != ""))' > "$out/pitangus-$version-images.json"

echo "Wrote $(ls "$out" | wc -l | tr -d ' ') files to $out"
