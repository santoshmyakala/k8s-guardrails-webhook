// Command guardrails-webhook is a Kubernetes validating admission webhook that enforces platform
// guardrails on workloads.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/santoshmyakala/k8s-guardrails-webhook/internal/admission"
	"github.com/santoshmyakala/k8s-guardrails-webhook/internal/certs"
	"github.com/santoshmyakala/k8s-guardrails-webhook/internal/policy"
)

func main() {
	addr := flag.String("addr", ":8443", "HTTPS address for admission requests")
	opsAddr := flag.String("ops-addr", ":9090", "HTTP address for /metrics, /healthz and /readyz")
	certFile := flag.String("tls-cert", "/etc/guardrails/tls/tls.crt", "TLS certificate (reloaded on change)")
	keyFile := flag.String("tls-key", "/etc/guardrails/tls/tls.key", "TLS private key (reloaded on change)")
	policyFile := flag.String("policy", "/etc/guardrails/policy/policy.yaml", "policy file")
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(log, *addr, *opsAddr, *certFile, *keyFile, *policyFile); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger, addr, opsAddr, certFile, keyFile, policyFile string) error {
	pol, err := policy.Load(policyFile)
	if err != nil {
		return err
	}
	reloader, err := certs.NewReloader(certFile, keyFile)
	if err != nil {
		return err
	}
	reloader.OnError = func(err error) { log.Error("certificate reload failed; serving the previous one", "err", err) }

	reg := prometheus.NewRegistry()
	reg.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	handler := &admission.Handler{Policy: pol, Metrics: admission.NewMetrics(reg), Log: log}

	mux := http.NewServeMux()
	mux.Handle("/validate", handler)
	webhook := &http.Server{
		Addr:              addr,
		Handler:           mux,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS13, GetCertificate: reloader.GetCertificate},
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       90 * time.Second,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn), // e.g. TLS handshake errors
	}

	ops := http.NewServeMux()
	ops.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{Registry: reg}))
	ok := func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) }
	ops.HandleFunc("/healthz", ok)
	ops.HandleFunc("/readyz", ok) // the policy and certificate are loaded before we listen
	opsServer := &http.Server{Addr: opsAddr, Handler: ops, ReadHeaderTimeout: 5 * time.Second}

	errs := make(chan error, 2)
	go func() { errs <- webhook.ListenAndServeTLS("", "") }()
	go func() { errs <- opsServer.ListenAndServe() }()
	log.Info("serving", "addr", addr, "opsAddr", opsAddr, "enforcement", pol.Enforcement,
		"allowedRegistries", pol.AllowedRegistries, "requiredLabels", pol.RequiredLabels)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	select {
	case err := <-errs:
		return err
	case <-ctx.Done():
	}
	// Endpoints are removed asynchronously after SIGTERM; keep serving briefly so in-flight
	// admission calls don't fail (failurePolicy: Fail would reject them).
	log.Info("shutting down")
	time.Sleep(3 * time.Second)
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = errors.Join(webhook.Shutdown(shutdown), opsServer.Shutdown(shutdown))
	return err
}
