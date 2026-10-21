# OCI-attested SBOM ingestion (experimental)

> **Security notice:** OCI SHA-256 integrity and subject binding are validated,
> but DSSE signatures and signer identity are **not** cryptographically verified.
> Unverified SBOM claims must not be treated as trusted vulnerability evidence.

## CLI

Ordinary Syft scans remain unchanged. Attested imports deliberately require the explicit registry source; a local Docker daemon image must not be confused with a remote tag that can change.

~~~sh
syft scan registry:ghcr.io/example/app:1.0 -o syft-json
~~~

To combine scanned software inventory with attested SBOM packages:

~~~sh
syft scan registry:ghcr.io/example/app:1.0 \
  --attested-sbom=additive -o syft-json
~~~

To use only the attached inventory, explicitly and with an error if none is found:

~~~sh
syft scan registry:ghcr.io/example/app:1.0 \
  --attested-sbom=replacement -o syft-json
~~~

Replacement mode ingests unverified assertions, rather than independently
examining filesystem contents. Do not rely on it alone for security gates.
Imported packages carry a FoundBy provenance label containing the OCI artifact
digest and the word unverified. If independently scanned and attested packages
have the same ID, scanned provenance is retained.

## Scope

- OCI 1.1 referrers discovery plus referrers-tag fallback for older registries.
- Sigstore bundle v0.3 JSON OCI layers containing DSSE in-toto Statement v1.
- CycloneDX JSON and SPDX JSON predicates decoded via Syft native decoders.
- Registry credentials and default Docker keychain through challenge-aware auth.
- Binding to the image digest resolved by Syft, without re-fetching a mutable tag.
- Resource ceilings: 64 referrer descriptors, 8 layers/manifest, index 2 MiB,
  manifest 512 KiB, blob 16 MiB and total download budget 64 MiB.
- Reject digest, size and subject mismatches, malformed relevant artifacts,
  invalid JSON, unsupported image sources, or unknown scan modes.
- Missing attestation: original scan unchanged in additive mode; explicit
  error in replacement mode.

## Validation

~~~sh
go test ./syft/ociattestation -count=1
go test -race ./syft/ociattestation -count=1
go test ./cmd/syft/internal/commands -run TestProduceScanSBOM -count=1
go vet ./syft/ociattestation ./cmd/syft/internal/commands
~~~

Known limitations to resolve before upstream delivery:
- Signature, Fulcio identity and transparency-log verification not implemented.
- Cross-document relationship and provenance encoding across all export formats
  requires maintainer review.
- Multi-architecture images whose attestations target an index digest instead
  of the resolved platform manifest require validation.
- Integration testing against a real GHCR GitHub Actions SBOM attestation
  is still required.
- The temporary fork-only development workflow must be dropped before a
  clean upstream PR.

See https://github.com/anchore/grype/issues/3604 for project background.
