package ociattestation

import (
	"strings"
	"testing"
)

func TestDecodeSBOMsCycloneDX(t *testing.T) {
	in := []Result{
		{
			Format:         "cyclonedx-json",
			Document:       []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[{"type":"library","name":"log4j-core","version":"2.14.1"}]}`),
			ImageDigest:    testImageSHA,
			ArtifactDigest: "sha256:" + strings.Repeat("a", 64),
			PredicateType:  CycloneDXPredicate,
		},
	}
	got, err := DecodeSBOMs(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Document == nil {
		t.Fatalf("unexpected decoded documents: %+v", got)
	}
	if got[0].Document.Artifacts.Packages.PackageCount() != 1 {
		t.Fatalf("missing packages: %d", got[0].Document.Artifacts.Packages.PackageCount())
	}
	packages := got[0].Document.Artifacts.Packages.Sorted()
	if len(packages) != 1 || packages[0].Name != "log4j-core" {
		t.Fatalf("unexpected packages: %+v", packages)
	}
	if got[0].ArtifactDigest != in[0].ArtifactDigest || got[0].SignatureVerified {
		t.Fatal("provenance was lost or unverified data was marked as verified")
	}
}

func TestDecodeSBOMsRejectsInvalidDocuments(t *testing.T) {
	tests := []struct {
		name   string
		result Result
		want   string
	}{
		{
			name:   "unsupported format",
			result: Result{Format: "syft-json", Document: []byte("{}")},
			want:   "unsupported",
		},
		{
			name:   "malformed document",
			result: Result{Format: "cyclonedx-json", Document: []byte("{invalid")},
			want:   "decode",
		},
		{
			name:   "false trust assertion",
			result: Result{Format: "cyclonedx-json", SignatureVerified: true},
			want:   "verified",
		},
		{
			name:   "format mismatch",
			result: Result{Format: "spdx-json", Document: []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[]}`)},
			want:   "mismatch",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecodeSBOMs([]Result{tc.result})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestDecodeSBOMsEmpty(t *testing.T) {
	got, err := DecodeSBOMs(nil)
	if err != nil || len(got) != 0 {
		t.Fatalf("expected empty result, got %v, %v", got, err)
	}
}
