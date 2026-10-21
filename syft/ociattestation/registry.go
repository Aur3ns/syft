package ociattestation

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft/source"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
)

// NewClientForImage binds OCI discovery to the image digest obtained during
// Syft source resolution. It never re-resolves a mutable image tag.
// Registry auth uses go-containerregistry's challenge-aware transport.
func NewClientForImage(ctx context.Context, reference string, description source.Description, opts *image.RegistryOptions) (*Client, string, error) {
	var metadata source.ImageMetadata
	switch v := description.Metadata.(type) {
	case source.ImageMetadata:
		metadata = v
	case *source.ImageMetadata:
		if v == nil {
			return nil, "", errors.New("image source has nil metadata")
		}
		metadata = *v
	default:
		return nil, "", errors.New("attested SBOMs are only supported for container images")
	}
	digest := metadata.ManifestDigest
	if !sha256Digest.MatchString(digest) {
		return nil, "", fmt.Errorf("resolved image manifest has invalid digest %q", digest)
	}

	// Syft accepts explicit source prefixes. They are not OCI registry names.
	reference = strings.TrimPrefix(reference, "registry:")
	if reference == "" {
		reference = metadata.UserInput
		reference = strings.TrimPrefix(reference, "registry:")
	}
	var nameOpts []name.Option
	if opts != nil && opts.InsecureUseHTTP {
		nameOpts = append(nameOpts, name.Insecure)
	}
	ref, err := name.ParseReference(reference, nameOpts...)
	if err != nil {
		return nil, "", fmt.Errorf("parse image registry reference: %w", err)
	}
	repo := ref.Context()
	// If Syft identified a canonical repository digest, prefer it only when
	// it refers to the requested registry/repository and to the same resolved
	// manifest. Do not replace this digest with another digest from a tag lookup.
	for _, repoDigest := range metadata.RepoDigests {
		candidate, err := name.ParseReference(repoDigest, nameOpts...)
		if err != nil || candidate.Context().Name() != repo.Name() {
			continue
		}
		if parsed, ok := candidate.(name.Digest); ok && parsed.DigestStr() == digest {
			repo = parsed.Context()
			break
		}
	}

	var transportBase http.RoundTripper = http.DefaultTransport
	if defaultTransport, ok := http.DefaultTransport.(*http.Transport); ok {
		cloned := defaultTransport.Clone()
		if opts != nil {
			if opts.InsecureSkipTLSVerify {
				if cloned.TLSClientConfig == nil {
					cloned.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
				}
				cloned.TLSClientConfig.InsecureSkipVerify = true //nolint:gosec // user explicitly requests insecure registry TLS
			}
			if opts.CAFileOrDir != "" {
				pool, err := registryCACertPool(opts.CAFileOrDir)
				if err != nil {
					return nil, "", err
				}
				if cloned.TLSClientConfig == nil {
					cloned.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
				}
				cloned.TLSClientConfig.RootCAs = pool
			}
		}
		transportBase = cloned
	}
	auth, err := registryAuthenticator(repo, opts)
	if err != nil {
		return nil, "", err
	}
	authTransport, err := transport.NewWithContext(ctx, repo.Registry, auth, transportBase, []string{repo.Scope(transport.PullScope)})
	if err != nil {
		return nil, "", fmt.Errorf("establish OCI registry authentication: %w", err)
	}
	return &Client{
		BaseURL:    repo.Registry.Scheme() + "://" + repo.RegistryStr(),
		Repository: repo.RepositoryStr(),
		HTTPClient: &http.Client{Transport: authTransport, Timeout: 30 * time.Second},
	}, digest, nil
}

func registryAuthenticator(repo name.Repository, opts *image.RegistryOptions) (authn.Authenticator, error) {
	if opts != nil {
		for _, cred := range opts.Credentials {
			if cred.Authority != "" && cred.Authority != repo.RegistryStr() && cred.Authority != repo.Registry.Name() {
				continue
			}
			if cred.Token != "" {
				return &authn.Bearer{Token: cred.Token}, nil
			}
			if cred.Username != "" || cred.Password != "" {
				return &authn.Basic{Username: cred.Username, Password: cred.Password}, nil
			}
		}
	}
	return authn.DefaultKeychain.Resolve(repo.Registry)
}

func registryCACertPool(location string) (*x509.CertPool, error) {
	pool, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("load system CA certificates: %w", err)
	}
	paths := []string{location}
	fi, err := os.Stat(location)
	if err != nil {
		return nil, fmt.Errorf("stat registry CA path: %w", err)
	}
	if fi.IsDir() {
		paths, err = filepath.Glob(filepath.Join(location, "*"))
		if err != nil {
			return nil, err
		}
	}
	loaded := false
	for _, path := range paths {
		if !strings.HasSuffix(path, ".crt") && !strings.HasSuffix(path, ".cert") && !strings.HasSuffix(path, ".pem") {
			continue
		}
		cert, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read registry CA certificate: %w", err)
		}
		if pool.AppendCertsFromPEM(cert) {
			loaded = true
		}
	}
	if !loaded {
		return nil, fmt.Errorf("registry CA path %q contains no usable PEM certificates", location)
	}
	return pool, nil
}
