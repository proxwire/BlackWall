# Release and supply-chain process

BlackWall releases are created only from GitHub-verified signed semantic
version tags. The release workflow rebuilds and tests the entire amd64 image,
publishes it to GHCR by immutable digest, signs that digest with Sigstore
keyless signing, attaches GitHub build provenance and an image SBOM
attestation, and uploads three CycloneDX 1.6 SBOMs plus checksums.

## Maintainer procedure

1. Update `lab/pyproject.toml`, `CHANGELOG.md`, the supported-platform matrix,
   and the third-party notice review.
2. Run the CI suite and inspect dependency/security audit results.
3. Create and push an annotated signed tag matching the project version:

   ```bash
   git tag -s v0.1.0 -m "BlackWall 0.1.0"
   git push origin v0.1.0
   ```

4. The release workflow rejects lightweight or GitHub-unverified tags. It
   publishes `ghcr.io/<owner>/blackwall:0.1.0` and `:latest` only after the
   source checks, image unit tests, benchmark admission, and reliability suite
   pass.

## Verification

Fetch the exact digest shown by the release rather than trusting a mutable tag:

```bash
cosign verify \
  --certificate-identity-regexp '^https://github.com/.+/BlackWall/.github/workflows/release.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/OWNER/blackwall@sha256:DIGEST

gh attestation verify oci://ghcr.io/OWNER/blackwall@sha256:DIGEST \
  --repo OWNER/BlackWall
```

Download `blackwall-image.cdx.json`, `blackwall-python.cdx.json`,
`blackwall-npm.cdx.json`, and `SHA256SUMS` from the matching GitHub release.
The image SBOM enumerates installed Debian, Python, and npm packages; the two
ecosystem SBOMs preserve the source-lock view.

## Prebuilt-image decision

The reviewed decision is to publish one Linux/amd64 image from signed release
tags only. This avoids floating CI images and gives users a verifiable digest,
but it also distributes a large hostile-input parsing surface. Consequently:

- the image is never a native-malware execution boundary;
- releases retain direct-tool notices and attach complete package inventories;
- the image is signed and attested, but signatures establish provenance, not
  safety;
- release consumers should update promptly, pin the digest, keep `--network
  none`, and preserve BlackWall's capability/read-only/resource restrictions;
- any new direct binary or license change blocks release until
  `THIRD_PARTY_NOTICES.md` and the redistribution review are updated.

## Controlled updates

The `Controlled dependency update` workflow accepts only packages in
`.github/dependency-update-policy.json` and exact, syntax-constrained versions.
It regenerates the appropriate uv or npm lock, builds the full image, runs all
inert fixtures and reliability checks, then opens a pull request. It cannot add
a new package or execute a caller-provided command. Direct binary tool pins
remain manual because their upstream artifact URLs, checksums, licenses, and
image smoke tests require human review.
