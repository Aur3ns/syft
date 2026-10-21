package ociattestation

import (
 "strings"
 "testing"
)

func TestNewSigstoreVerifierRequiresExplicitIdentity(t *testing.T) {
 cases := []TrustPolicy{
  {},
  {Issuer:"https://token.actions.githubusercontent.com"},
  {Identity:"https://github.com/example/repo/.github/workflows/release.yml@refs/heads/main"},
 }
 for _, policy := range cases {
  if verifier, err := NewSigstoreVerifier(policy); err == nil || verifier != nil {
   t.Fatalf("insecure identity configuration accepted: %+v", policy)
  }
 }
}

func TestSigstoreVerifierRejectsAbsentEngine(t *testing.T) {
 var verifier *SigstoreVerifier
 err := verifier.VerifyBundle([]byte("{}"), testImageSHA)
 if err == nil || !strings.Contains(err.Error(), "no Sigstore verifier") {
  t.Fatalf("missing verifier was accepted: %v", err)
 }
}

func TestSigstoreVerifierRejectsInvalidDigestBeforeTrustChecks(t *testing.T) {
 verifier := &SigstoreVerifier{}
 if err := verifier.VerifyBundle([]byte("{}"), "sha256:invalid"); err == nil {
  t.Fatal("malformed image digest was accepted")
 }
}
