package ociattestation

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// TrustPolicy requires BOTH an OIDC certificate issuer and an exact
// certificate subject identity. Callers cannot request an identity wildcard.
// The Sigstore trusted root is fetched through Sigstore TUF.
type TrustPolicy struct {
	Issuer string
	Identity string
}

// SigstoreVerifier enforces Fulcio certificate-chain validation,
// certificate identity, Rekor transparency-log evidence and trusted observer
// timestamps. Without this policy, a valid signature alone is insufficient.
type SigstoreVerifier struct {
	engine *verify.Verifier
	identity verify.CertificateIdentity
}

func NewSigstoreVerifier(policy TrustPolicy) (*SigstoreVerifier, error) {
	if strings.TrimSpace(policy.Issuer) == "" || strings.TrimSpace(policy.Identity) == "" {
		return nil, errors.New("both exact certificate issuer and signing identity are required")
	}
	identity, err := verify.NewShortCertificateIdentity(policy.Issuer, "", policy.Identity, "")
	if err != nil {
		return nil, fmt.Errorf("configure certificate identity: %w", err)
	}
	trustedRoot, err := root.FetchTrustedRoot()
	if err != nil {
		return nil, fmt.Errorf("fetch Sigstore trusted root: %w", err)
	}
	engine, err := verify.NewVerifier(trustedRoot,
		verify.WithSignedCertificateTimestamps(1),
		verify.WithTransparencyLog(1),
		verify.WithObserverTimestamps(1),
	)
	if err != nil {
		return nil, fmt.Errorf("configure Sigstore verification: %w", err)
	}
	return &SigstoreVerifier{engine:engine, identity:identity}, nil
}

// VerifyBundle checks the exact downloaded bundle, not a reconstructed
// statement. The expected OCI image digest is enforced by the Sigstore
// verifier's artifact policy, independently of existing in-toto checks.
func (v *SigstoreVerifier) VerifyBundle(raw []byte, imageDigest string) error {
	if v == nil || v.engine == nil {
		return errors.New("no Sigstore verifier configured")
	}
	if !sha256Digest.MatchString(imageDigest) {
		return errors.New("expected image digest must be sha256")
	}
	var entity bundle.Bundle
	if err := json.Unmarshal(raw, &entity); err != nil {
		return fmt.Errorf("parse Sigstore bundle: %w", err)
	}
	digest, err := hex.DecodeString(strings.TrimPrefix(imageDigest, "sha256:"))
	if err != nil {
		return fmt.Errorf("decode image digest: %w", err)
	}
	if _, err := v.engine.Verify(&entity, verify.NewPolicy(
		verify.WithArtifactDigest("sha256", digest),
		verify.WithCertificateIdentity(v.identity),
	)); err != nil {
		return fmt.Errorf("Sigstore signature, identity or transparency verification failed: %w", err)
	}
	return nil
}
