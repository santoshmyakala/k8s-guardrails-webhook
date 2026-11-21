// Package certs serves a TLS certificate that is reloaded when its files change, so a rotation by
// cert-manager (or a re-mounted Secret) needs no restart.
package certs

import (
	"crypto/tls"
	"fmt"
	"os"
	"sync"
	"time"
)

// Reloader loads a key pair and reloads it when either file's modification time changes. Files
// are checked at most once per Interval; a failed reload keeps serving the previous certificate.
type Reloader struct {
	CertFile, KeyFile string
	Interval          time.Duration
	OnError           func(error)

	mu        sync.Mutex
	cert      *tls.Certificate
	certMod   time.Time
	keyMod    time.Time
	lastCheck time.Time
	now       func() time.Time
}

// NewReloader loads the key pair once and fails if it is unusable.
func NewReloader(certFile, keyFile string) (*Reloader, error) {
	r := &Reloader{CertFile: certFile, KeyFile: keyFile, Interval: 10 * time.Second, now: time.Now}
	if err := r.reload(); err != nil {
		return nil, err
	}
	return r, nil
}

func modTime(path string) (time.Time, error) {
	st, err := os.Stat(path)
	if err != nil {
		return time.Time{}, err
	}
	return st.ModTime(), nil
}

func (r *Reloader) reload() error {
	cm, err := modTime(r.CertFile)
	if err != nil {
		return err
	}
	km, err := modTime(r.KeyFile)
	if err != nil {
		return err
	}
	if r.cert != nil && cm.Equal(r.certMod) && km.Equal(r.keyMod) {
		return nil
	}
	c, err := tls.LoadX509KeyPair(r.CertFile, r.KeyFile)
	if err != nil {
		return fmt.Errorf("loading key pair: %w", err)
	}
	r.cert, r.certMod, r.keyMod = &c, cm, km
	return nil
}

// GetCertificate is a tls.Config.GetCertificate callback.
func (r *Reloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if now := r.now(); now.Sub(r.lastCheck) >= r.Interval {
		r.lastCheck = now
		if err := r.reload(); err != nil && r.OnError != nil {
			r.OnError(err)
		}
	}
	return r.cert, nil
}
