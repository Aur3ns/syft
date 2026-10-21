// Package ociattestation discovers SBOM statements attached to OCI images.
// It checks OCI content digests and image subject binding. It does NOT verify
// DSSE signatures or establish trust in the SBOM's assertions.
package ociattestation

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

const (
	IndexMediaType             = "application/vnd.oci.image.index.v1+json"
	ManifestMediaType          = "application/vnd.oci.image.manifest.v1+json"
	BundleMediaType            = "application/vnd.dev.sigstore.bundle.v0.3+json"
	DSSEPayloadType            = "application/vnd.in-toto+json"
	CycloneDXPredicate         = "https://cyclonedx.org/bom"
	SPDXPredicate              = "https://spdx.dev/Document"
	defaultIndexLimit    int64 = 2 << 20
	defaultManifestLimit int64 = 512 << 10
	defaultBlobLimit     int64 = 16 << 20
	defaultTotalLimit    int64 = 64 << 20
	maxAttestations            = 64
)

var (
	sha256Digest = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	repoPart     = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*$`)
)

// Result contains an untrusted SBOM. SignatureVerified is always false.
// Callers must never present content-digest checks as signature verification.
type Result struct {
	Format            string
	Document          []byte
	ImageDigest       string
	ArtifactDigest    string
	PredicateType     string
	SignatureVerified bool
}

// Client uses a caller-supplied HTTP client for registry credentials and TLS.
// BaseURL identifies the registry origin, not the repository.
type Client struct {
	BaseURL       string
	Repository    string
	HTTPClient    *http.Client
	IndexLimit    int64
	ManifestLimit int64
	BlobLimit     int64
	TotalLimit    int64
}

type descriptor struct {
	MediaType    string            `json:"mediaType"`
	Digest       string            `json:"digest"`
	Size         int64             `json:"size"`
	ArtifactType string            `json:"artifactType"`
	Annotations  map[string]string `json:"annotations"`
}

type index struct {
	Manifests []descriptor `json:"manifests"`
}

type manifest struct {
	MediaType    string       `json:"mediaType"`
	ArtifactType string       `json:"artifactType"`
	Subject      *descriptor  `json:"subject"`
	Layers       []descriptor `json:"layers"`
}

type bundle struct {
	DSSEEnvelope struct {
		Payload     string `json:"payload"`
		PayloadType string `json:"payloadType"`
	} `json:"dsseEnvelope"`
}

type statement struct {
	Type          string `json:"_type"`
	PredicateType string `json:"predicateType"`
	Subject       []struct {
		Name   string            `json:"name"`
		Digest map[string]string `json:"digest"`
	} `json:"subject"`
	Predicate json.RawMessage `json:"predicate"`
}

// Discover retrieves OCI 1.1 referrers. Missing referrers return no results;
// malformed relevant artifacts fail closed. SHA-256 is the supported algorithm.
func (c *Client) Discover(ctx context.Context, imageDigest string) ([]Result, error) {
	if !sha256Digest.MatchString(imageDigest) {
		return nil, fmt.Errorf("invalid image digest %q: expected sha256:<64 hex>", imageDigest)
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	base, err := url.Parse(c.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid registry URL: %w", err)
	}
	contents, notFound, err := c.request(ctx, base, "/v2/"+c.Repository+"/referrers/"+imageDigest, c.indexLimit(), "", true)
	if err != nil {
		return nil, fmt.Errorf("list OCI referrers: %w", err)
	}
	if notFound {
		return nil, nil
	}
	remaining := c.totalLimit() - int64(len(contents))
	if remaining < 0 {
		return nil, errors.New("OCI referrers exceed total byte budget")
	}
	var idx index
	if err := json.Unmarshal(contents, &idx); err != nil {
		return nil, fmt.Errorf("decode OCI referrers: %w", err)
	}
	if len(idx.Manifests) > maxAttestations {
		return nil, fmt.Errorf("too many OCI referrers: %d > %d", len(idx.Manifests), maxAttestations)
	}
	results := make([]Result, 0)
	seen := make(map[string]bool)
	for _, desc := range idx.Manifests {
		if desc.ArtifactType != "" && desc.ArtifactType != BundleMediaType {
			continue
		}
		predHint := desc.Annotations["dev.sigstore.bundle.predicateType"]
		if predHint != "" && predHint != CycloneDXPredicate && predHint != SPDXPredicate {
			continue
		}
		if desc.ArtifactType == "" && desc.Annotations["dev.sigstore.bundle.content"] != "dsse-envelope" {
			continue
		}
		if seen[desc.Digest] {
			continue
		}
		seen[desc.Digest] = true
		limit := min(c.manifestLimit(), remaining)
		if err := checkDescriptor(desc, limit); err != nil {
			return nil, err
		}
		manifestBytes, _, err := c.request(ctx, base, "/v2/"+c.Repository+"/manifests/"+desc.Digest, limit, desc.Digest, false)
		if err != nil {
			return nil, fmt.Errorf("fetch referrer %s: %w", desc.Digest, err)
		}
		remaining -= int64(len(manifestBytes))
		if int64(len(manifestBytes)) != desc.Size {
			return nil, fmt.Errorf("OCI referrer descriptor size mismatch for %s", desc.Digest)
		}
		var m manifest
		if err := json.Unmarshal(manifestBytes, &m); err != nil {
			return nil, fmt.Errorf("decode referrer manifest %s: %w", desc.Digest, err)
		}
		if m.MediaType != "" && m.MediaType != ManifestMediaType {
			return nil, fmt.Errorf("unsupported OCI manifest media type %q", m.MediaType)
		}
		if m.ArtifactType != "" && m.ArtifactType != BundleMediaType {
			continue
		}
		if m.Subject == nil || m.Subject.Digest != imageDigest {
			return nil, fmt.Errorf("OCI referrer %s is not attached to image digest %s", desc.Digest, imageDigest)
		}
		if len(m.Layers) == 0 {
			return nil, fmt.Errorf("OCI referrer %s has no layers", desc.Digest)
		}
		for _, layer := range m.Layers {
			if layer.MediaType != BundleMediaType {
				continue
			}
			limit := min(c.blobLimit(), remaining)
			if err := checkDescriptor(layer, limit); err != nil {
				return nil, err
			}
			b, _, err := c.request(ctx, base, "/v2/"+c.Repository+"/blobs/"+layer.Digest, limit, layer.Digest, false)
			if err != nil {
				return nil, fmt.Errorf("fetch SBOM bundle %s: %w", layer.Digest, err)
			}
			remaining -= int64(len(b))
			if int64(len(b)) != layer.Size {
				return nil, fmt.Errorf("OCI blob descriptor size mismatch for %s", layer.Digest)
			}
			result, compatible, err := decodeBundle(b, imageDigest, desc.Digest)
			if err != nil {
				return nil, fmt.Errorf("decode SBOM bundle %s: %w", layer.Digest, err)
			}
			if !compatible {
				continue
			}
			if predHint != "" && predHint != result.PredicateType {
				return nil, errors.New("referrer annotation does not match attested predicate type")
			}
			results = append(results, result)
		}
	}
	return results, nil
}

func (c *Client) validate() error {
	u, err := url.Parse(c.BaseURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
		return errors.New("registry URL must be an http(s) origin without credentials, query or path")
	}
	if strings.Contains(c.Repository, "..") || c.Repository == "" {
		return errors.New("invalid OCI repository")
	}
	for _, p := range strings.Split(c.Repository, "/") {
		if !repoPart.MatchString(p) {
			return fmt.Errorf("invalid OCI repository component %q", p)
		}
	}
	return nil
}
func (c *Client) indexLimit() int64 {
	if c.IndexLimit > 0 { return c.IndexLimit }
	return defaultIndexLimit
}
func (c *Client) manifestLimit() int64 {
	if c.ManifestLimit > 0 { return c.ManifestLimit }
	return defaultManifestLimit
}
func (c *Client) blobLimit() int64 {
	if c.BlobLimit > 0 { return c.BlobLimit }
	return defaultBlobLimit
}
func (c *Client) totalLimit() int64 {
	if c.TotalLimit > 0 { return c.TotalLimit }
	return defaultTotalLimit
}
func checkDescriptor(d descriptor, limit int64) error {
	if !sha256Digest.MatchString(d.Digest) {
		return fmt.Errorf("unsupported or malformed OCI digest %q", d.Digest)
	}
	if d.Size < 0 || d.Size > limit {
		return fmt.Errorf("OCI descriptor %s size %d outside allowed maximum %d", d.Digest, d.Size, limit)
	}
	return nil
}

func (c *Client) request(ctx context.Context, origin *url.URL, path string, limit int64, digest string, allow404 bool) ([]byte, bool, error) {
	endpoint := *origin
	endpoint.Path = path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, false, err
	}
	if digest == "" { req.Header.Set("Accept", IndexMediaType) } else { req.Header.Set("Accept", ManifestMediaType+", "+BundleMediaType) }
	client := c.HTTPClient
	if client == nil { client = http.DefaultClient }
	resp, err := client.Do(req)
	if err != nil { return nil, false, err }
	defer resp.Body.Close()
	if allow404 && resp.StatusCode == http.StatusNotFound { return nil, true, nil }
	if resp.StatusCode != http.StatusOK { return nil, false, fmt.Errorf("unexpected registry HTTP status %d", resp.StatusCode) }
	if resp.ContentLength > limit { return nil, false, fmt.Errorf("OCI response exceeds %d bytes", limit) }
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil { return nil, false, err }
	if int64(len(data)) > limit { return nil, false, fmt.Errorf("OCI response exceeds %d bytes", limit) }
	if digest != "" {
		sum := sha256.Sum256(data)
		if got := "sha256:"+hex.EncodeToString(sum[:]); got != digest {
			return nil, false, fmt.Errorf("OCI content digest mismatch: expected %s, got %s", digest, got)
		}
	}
	return data, false, nil
}

func decodeBundle(raw []byte, imageDigest, artifactDigest string) (Result, bool, error) {
	var b bundle
	if err := json.Unmarshal(raw, &b); err != nil { return Result{}, false, err }
	if b.DSSEEnvelope.Payload == "" { return Result{}, false, errors.New("Sigstore bundle is missing DSSE payload") }
	if b.DSSEEnvelope.PayloadType != DSSEPayloadType { return Result{}, false, fmt.Errorf("unsupported DSSE payload type %q", b.DSSEEnvelope.PayloadType) }
	payload, err := base64.StdEncoding.Strict().DecodeString(b.DSSEEnvelope.Payload)
	if err != nil { return Result{}, false, fmt.Errorf("invalid DSSE base64 payload: %w", err) }
	var s statement
	if err := json.Unmarshal(payload, &s); err != nil { return Result{}, false, fmt.Errorf("invalid in-toto statement: %w", err) }
	if s.Type != "https://in-toto.io/Statement/v1" { return Result{}, false, fmt.Errorf("unsupported statement type %q", s.Type) }
	if s.PredicateType != CycloneDXPredicate && s.PredicateType != SPDXPredicate { return Result{}, false, nil }
	hexDigest := strings.TrimPrefix(imageDigest, "sha256:")
	bound := false
	for _, sub := range s.Subject {
		if sub.Digest["sha256"] == hexDigest { bound = true; break }
	}
	if !bound { return Result{}, false, errors.New("in-toto subject digest does not match requested image") }
	if len(s.Predicate) == 0 || string(s.Predicate) == "null" { return Result{}, false, errors.New("SBOM predicate is empty") }
	var probe struct {
		BomFormat string `json:"bomFormat"`
		SPDXVersion string `json:"spdxVersion"`
	}
	if err := json.Unmarshal(s.Predicate, &probe); err != nil { return Result{}, false, fmt.Errorf("SBOM predicate is not JSON: %w", err) }
	var format string
	switch s.PredicateType {
	case CycloneDXPredicate:
		if probe.BomFormat != "CycloneDX" { return Result{}, false, errors.New("CycloneDX predicate lacks bomFormat") }
		format = "cyclonedx-json"
	case SPDXPredicate:
		if !strings.HasPrefix(probe.SPDXVersion, "SPDX-") { return Result{}, false, errors.New("SPDX predicate lacks spdxVersion") }
		format = "spdx-json"
	}
	return Result{Format:format, Document:append([]byte(nil),s.Predicate...), ImageDigest:imageDigest, ArtifactDigest:artifactDigest, PredicateType:s.PredicateType, SignatureVerified:false}, true, nil
}
