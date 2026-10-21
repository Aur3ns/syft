package ociattestation

import (
	"strings"
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

func samplePackage(name, foundBy string) pkg.Package {
	p := pkg.Package{Name: name, Version: "1.0.0", FoundBy: foundBy, Type: pkg.NpmPkg}
	p.SetID()
	return p
}

func sampleSBOM(pkgs ...pkg.Package) *sbom.SBOM {
	return &sbom.SBOM{
		Source:    source.Description{Name: "image", ID: string(testImageSHA)},
		Artifacts: sbom.Artifacts{Packages: pkg.NewCollection(pkgs...)},
	}
}

func sampleDocument(s *sbom.SBOM) DecodedSBOM {
	return DecodedSBOM{Document: s, ImageDigest: testImageSHA, ArtifactDigest: "sha256:" + strings.Repeat("a", 64)}
}

func TestCombineAdditivePreservesIndependentScan(t *testing.T) {
	scanned := samplePackage("scanned-only", "npm-cataloger")
	attested := samplePackage("attested-only", "SBOM")
	base := sampleSBOM(scanned)
	got, err := Combine(base, []DecodedSBOM{sampleDocument(sampleSBOM(attested))}, AdditiveMode)
	if err != nil {
		t.Fatal(err)
	}
	if got.Artifacts.Packages.PackageCount() != 2 {
		t.Fatalf("got %d packages, want 2", got.Artifacts.Packages.PackageCount())
	}
	if p := got.Artifacts.Packages.Package(scanned.ID()); p == nil || p.FoundBy != "npm-cataloger" {
		t.Fatalf("scanned provenance changed: %+v", p)
	}
	if p := got.Artifacts.Packages.Package(attested.ID()); p == nil || !strings.HasPrefix(p.FoundBy, "oci-attested-sbom-unverified:sha256:") {
		t.Fatalf("attested provenance missing: %+v", p)
	}
	if got.Source.Name != "image" {
		t.Fatal("source not preserved")
	}
}

func TestCombineReplacementOmitsScannedPackages(t *testing.T) {
	scanned := samplePackage("only-in-scan", "cataloger")
	attested := samplePackage("only-in-attestation", "sbom")
	got, err := Combine(sampleSBOM(scanned), []DecodedSBOM{sampleDocument(sampleSBOM(attested))}, ReplacementMode)
	if err != nil {
		t.Fatal(err)
	}
	if got.Artifacts.Packages.PackageCount() != 1 || got.Artifacts.Packages.Package(scanned.ID()) != nil {
		t.Fatal("replacement retained image-scan packages")
	}
	if p := got.Artifacts.Packages.Package(attested.ID()); p == nil || !strings.Contains(p.FoundBy, "unverified") {
		t.Fatal("attested package lacks unverified provenance")
	}
}

func TestCombineDuplicateCannotRelabelScannedPackage(t *testing.T) {
	scanned := samplePackage("openssl", "rpm-cataloger")
	attested := samplePackage("openssl", "attestation")
	got, err := Combine(sampleSBOM(scanned), []DecodedSBOM{sampleDocument(sampleSBOM(attested))}, AdditiveMode)
	if err != nil {
		t.Fatal(err)
	}
	if got.Artifacts.Packages.PackageCount() != 1 {
		t.Fatal("duplicate package added")
	}
	if got.Artifacts.Packages.Package(scanned.ID()).FoundBy != "rpm-cataloger" {
		t.Fatal("unverified attestation overwrote scanned evidence")
	}
}

func TestCombinePreservesPackageRelationships(t *testing.T) {
	parent := samplePackage("parent", "attested")
	dependency := samplePackage("dependency", "attested")
	s := sampleSBOM(parent, dependency)
	s.Relationships = []artifact.Relationship{{From: parent, To: dependency, Type: artifact.DependencyOfRelationship}}
	out, err := Combine(sampleSBOM(), []DecodedSBOM{sampleDocument(s)}, AdditiveMode)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Relationships) != 1 {
		t.Fatalf("expected package relationship, got %d", len(out.Relationships))
	}
	if out.Relationships[0].From.ID() != parent.ID() || out.Relationships[0].To.ID() != dependency.ID() {
		t.Fatal("unexpected relationship IDs")
	}
}

func TestCombineRejectsUnsafeInputs(t *testing.T) {
	for _, tc := range []struct {
		name string
		base *sbom.SBOM
		docs []DecodedSBOM
		mode Mode
	}{
		{"nil base", nil, nil, AdditiveMode},
		{"bad mode", sampleSBOM(), nil, "guess"},
		{"replace without attestation", sampleSBOM(), nil, ReplacementMode},
		{"nil attested document", sampleSBOM(), []DecodedSBOM{{}}, AdditiveMode},
		{"false signature claim", sampleSBOM(), []DecodedSBOM{{Document: sampleSBOM(), SignatureVerified: true}}, AdditiveMode},
		{"missing package name", sampleSBOM(), []DecodedSBOM{sampleDocument(sampleSBOM(pkg.Package{}))}, AdditiveMode},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Combine(tc.base, tc.docs, tc.mode); err == nil {
				t.Fatalf("accepted %s", tc.name)
			}
		})
	}
}
