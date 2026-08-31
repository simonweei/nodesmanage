package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"runtime"
	"testing"
	"time"
)

type fakeCertificateIssuer struct {
	calls    int
	issueErr error
	now      time.Time
	lifetime time.Duration
}

func (f *fakeCertificateIssuer) Issue(requirement certificateRequirement, _ *managedCertificate) (*issuedCertificate, error) {
	f.calls++
	if f.issueErr != nil {
		return nil, f.issueErr
	}
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(int64(f.calls)),
		Subject:      pkix.Name{CommonName: requirement.Domain},
		DNSNames:     []string{requirement.Domain},
		NotBefore:    f.now.Add(-time.Hour),
		NotAfter:     f.now.Add(f.lifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}
	privateDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	return &issuedCertificate{
		Certificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}),
		PrivateKey:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privateDER}),
		Metadata:    certificateMetadata{Domain: requirement.Domain, CertURL: "https://ca.example/cert/1"},
	}, nil
}

func TestCertificateManagerSharesOneCertificatePerDomain(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("managed certificate activation uses Linux symbolic links")
	}
	now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	issuer := &fakeCertificateIssuer{now: now, lifetime: 90 * 24 * time.Hour}
	manager := &certificateManager{root: t.TempDir(), issuer: issuer, now: func() time.Time { return now }}
	requirements := []certificateRequirement{
		{Domain: "shared.example.com", Email: "ops@example.com"},
		{Domain: "shared.example.com", Email: "ops@example.com"},
	}
	changed, status, err := manager.Ensure(requirements)
	if err != nil {
		t.Fatal(err)
	}
	if !changed || issuer.calls != 1 {
		t.Fatalf("changed=%v issuer calls=%d, want true and 1", changed, issuer.calls)
	}
	if len(status.Domains) != 1 || status.Domains[0] != "shared.example.com" {
		t.Fatalf("unexpected domains: %#v", status.Domains)
	}
	if _, err := loadManagedCertificate(manager.root, "shared.example.com"); err != nil {
		t.Fatalf("load managed certificate: %v", err)
	}
	changed, _, err = manager.Ensure(requirements)
	if err != nil || changed || issuer.calls != 1 {
		t.Fatalf("second ensure changed=%v calls=%d err=%v", changed, issuer.calls, err)
	}
}

func TestCertificateManagerBacksOffAfterIssuanceFailure(t *testing.T) {
	now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	issuer := &fakeCertificateIssuer{issueErr: errors.New("challenge unavailable"), now: now, lifetime: 90 * 24 * time.Hour}
	manager := &certificateManager{root: t.TempDir(), issuer: issuer, now: func() time.Time { return now }}
	requirements := []certificateRequirement{{Domain: "retry.example.com", Email: "ops@example.com"}}
	if _, _, err := manager.Ensure(requirements); err == nil {
		t.Fatal("expected initial issuance failure")
	}
	if _, _, err := manager.Ensure(requirements); err == nil {
		t.Fatal("expected deferred retry failure")
	}
	if issuer.calls != 1 {
		t.Fatalf("issuer calls=%d, want 1 during backoff", issuer.calls)
	}
}

func TestCertificateManagerRejectsConflictingEmails(t *testing.T) {
	manager := &certificateManager{root: t.TempDir(), issuer: &fakeCertificateIssuer{}, now: time.Now}
	_, _, err := manager.Ensure([]certificateRequirement{
		{Domain: "shared.example.com", Email: "ops@example.com"},
		{Domain: "shared.example.com", Email: "security@example.com"},
	})
	if err == nil {
		t.Fatal("expected conflicting email error")
	}
}
