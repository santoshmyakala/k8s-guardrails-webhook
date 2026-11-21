package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writePair writes a fresh self-signed certificate for cn and sets the files' mtime.
func writePair(t *testing.T, dir, cn string, mtime time.Time) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	for name, block := range map[string]*pem.Block{
		"tls.crt": {Type: "CERTIFICATE", Bytes: der},
		"tls.key": {Type: "EC PRIVATE KEY", Bytes: keyDER},
	} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, pem.EncodeToMemory(block), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, mtime, mtime); err != nil {
			t.Fatal(err)
		}
	}
}

func commonName(t *testing.T, r *Reloader) string {
	t.Helper()
	c, err := r.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return leaf.Subject.CommonName
}

func TestRotationIsPickedUpWithoutRestart(t *testing.T) {
	dir := t.TempDir()
	t0 := time.Now().Add(-time.Minute)
	writePair(t, dir, "first", t0)

	r, err := NewReloader(filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"))
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Now()
	r.now = func() time.Time { return clock }
	if got := commonName(t, r); got != "first" {
		t.Fatalf("got %q", got)
	}

	writePair(t, dir, "rotated", t0.Add(30*time.Second))
	if got := commonName(t, r); got != "first" {
		t.Fatalf("files must not be re-checked inside the interval, got %q", got)
	}
	clock = clock.Add(r.Interval)
	if got := commonName(t, r); got != "rotated" {
		t.Fatalf("rotation not picked up, got %q", got)
	}
}

func TestBrokenRotationKeepsServingThePreviousCertificate(t *testing.T) {
	dir := t.TempDir()
	writePair(t, dir, "good", time.Now().Add(-time.Minute))
	r, err := NewReloader(filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"))
	if err != nil {
		t.Fatal(err)
	}
	var reported error
	r.OnError = func(err error) { reported = err }
	clock := time.Now()
	r.now = func() time.Time { return clock.Add(time.Hour) }

	if err := os.WriteFile(filepath.Join(dir, "tls.key"), []byte("half-written"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := commonName(t, r); got != "good" {
		t.Fatalf("got %q", got)
	}
	if reported == nil {
		t.Fatal("the failed reload should be reported")
	}
}

func TestUnusableInitialCertificateFailsFast(t *testing.T) {
	if _, err := NewReloader("/nonexistent/tls.crt", "/nonexistent/tls.key"); err == nil {
		t.Fatal("expected an error")
	}
}
