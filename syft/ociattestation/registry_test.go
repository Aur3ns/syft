package ociattestation

import (
	"context"
	"strings"
	"testing"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft/source"
)

func TestNewClientForImageUsesResolvedDigest(t *testing.T) {
	f := newRegistryFixture()
	f.addSBOM(t, testImageSHA, CycloneDXPredicate, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[{"name":"openssl","version":"1.0","type":"library"}]}`))
	srv := f.server(t)
	// HTTPS is not required by the local test registry; production defaults to HTTPS.
	reference := strings.TrimPrefix(srv.URL, "http://") + "/org/repo:latest"
	meta := source.Description{Metadata: source.ImageMetadata{ManifestDigest:testImageSHA}}
	regOpts := &image.RegistryOptions{InsecureUseHTTP:true}
	client, digest, err := NewClientForImage(context.Background(),reference,meta,regOpts)
	if err != nil {t.Fatal(err)}
	if digest != testImageSHA {t.Fatalf("digest %q differs from resolved image",digest)}
	if client.Repository!="org/repo" || client.BaseURL!=srv.URL {t.Fatalf("unexpected registry location: %q / %q",client.Repository,client.BaseURL)}
	results,err:=client.Discover(context.Background(),digest)
	if err != nil {t.Fatal(err)}
	if len(results)!=1 {t.Fatalf("expected one attested SBOM, got %d",len(results))}
	imported,err:=Import(context.Background(),reference,meta,regOpts)
	if err!=nil {t.Fatal(err)}
	if len(imported)!=1 || imported[0].Document.Artifacts.Packages.PackageCount()!=1 {t.Fatalf("unexpected decoded inventory: %+v",imported)}
}

func TestNewClientForImageRejectsInvalidInputs(t *testing.T) {
	validMeta:=source.Description{Metadata:source.ImageMetadata{ManifestDigest:testImageSHA}}
	opts:=&image.RegistryOptions{InsecureUseHTTP:true}
	for _,tc:=range []struct{name string;ref string;source source.Description}{
		{"non-image","localhost:5000/org/repo:latest",source.Description{}},
		{"bad resolved digest","localhost:5000/org/repo:latest",source.Description{Metadata:source.ImageMetadata{ManifestDigest:"sha256:malformed"}}},
		{"bad registry reference","invalid reference with spaces",validMeta},
	}{
		t.Run(tc.name,func(t *testing.T){
			if _,_,err:=NewClientForImage(context.Background(),tc.ref,tc.source,opts);err==nil {t.Fatal("expected invalid metadata/reference error")}
		})
	}
}
