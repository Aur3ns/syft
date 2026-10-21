package ociattestation

import (
	"context"
	"errors"
	"fmt"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

// Mode controls whether attested packages are added to an independently
// cataloged image or replace them. Every mode is explicitly opt-in.
type Mode string

const (
	AdditiveMode    Mode = "additive"
	ReplacementMode Mode = "replacement"
)

// Import discovers and decodes OCI-attested SBOMs bound to Syft's resolved
// image digest, preserving provenance for the subsequent merge step.
func Import(ctx context.Context, reference string, description source.Description, registryOptions *image.RegistryOptions) ([]DecodedSBOM, error) {
	client, digest, err := NewClientForImage(ctx, reference, description, registryOptions)
	if err != nil {
		return nil, err
	}
	attestations, err := client.Discover(ctx, digest)
	if err != nil {
		return nil, fmt.Errorf("discover attested SBOMs: %w", err)
	}
	return DecodeSBOMs(attestations)
}

// Combine merges decoded *unverified* attestations with the catalog or
// constructs a replacement catalog. Identical packages already discovered
// by a local scan are not relabeled, so unverified claims cannot replace the
// stronger, independently observed provenance.
//
// Signature verification is NOT performed here. An opt-in mode does not imply
// trusted content. Downstream users must never assume these claims are signed
// or cryptographically verified.
func Combine(base *sbom.SBOM, docs []DecodedSBOM, mode Mode) (*sbom.SBOM, error) {
	if base == nil {
		return nil, errors.New("image SBOM is nil")
	}
	if mode != AdditiveMode && mode != ReplacementMode {
		return nil, fmt.Errorf("unknown attested SBOM mode %q", mode)
	}
	if mode == ReplacementMode && len(docs) == 0 {
		return nil, errors.New("replacement requested, but no usable attested SBOM was found")
	}
	if base.Artifacts.Packages == nil {
		return nil, errors.New("image SBOM has no package collection")
	}

	output := *base
	if mode == ReplacementMode {
		output.Artifacts = sbom.Artifacts{Packages: pkg.NewCollection()}
		output.Relationships = nil
	}
	seen := make(map[string]bool, len(output.Relationships))
	for _, rel := range output.Relationships {
		if rel.From != nil && rel.To != nil {
			seen[relationshipKey(rel)] = true
		}
	}
	for i, doc := range docs {
		if doc.Document == nil || doc.Document.Artifacts.Packages == nil {
			return nil, fmt.Errorf("attested SBOM %d has no packages", i)
		}
		if doc.SignatureVerified {
			return nil, fmt.Errorf("attested SBOM %d cannot claim signature verification", i)
		}
		label := "oci-attested-sbom-unverified:" + doc.ArtifactDigest
		for p := range doc.Document.Artifacts.Packages.Enumerate() {
			if !pkg.IsValid(&p) {
				return nil, fmt.Errorf("attested SBOM %d contains package with no name", i)
			}
			if output.Artifacts.Packages.Package(p.ID()) != nil {
				// Existing independently scanned packages take priority.
				continue
			}
			p.FoundBy = label
			output.Artifacts.Packages.Add(p)
		}
		for _, rel := range doc.Document.Relationships {
			if rel.From == nil || rel.To == nil {
				continue
			}
			from := output.Artifacts.Packages.Package(rel.From.ID())
			to := output.Artifacts.Packages.Package(rel.To.ID())
			if from == nil || to == nil {
				// Avoid cross-document file/source relationships.
				continue
			}
			key := relationshipKey(rel)
			if !seen[key] {
				seen[key] = true
				output.Relationships = append(output.Relationships, artifact.Relationship{
					From: *from, To: *to, Type: rel.Type, Data: rel.Data,
				})
			}
		}
	}
	return &output, nil
}

func relationshipKey(r artifact.Relationship) string {
	return string(r.From.ID()) + "\x00" + string(r.To.ID()) + "\x00" + string(r.Type)
}
