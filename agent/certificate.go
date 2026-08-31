package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

const certificateRenewBefore = 30 * 24 * time.Hour

var managedDomainPattern = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

type certificateRequirement struct {
	Domain string `json:"domain"`
	Email  string `json:"email"`
}

type certificateMetadata struct {
	Domain        string `json:"domain"`
	CertURL       string `json:"cert_url,omitempty"`
	CertStableURL string `json:"cert_stable_url,omitempty"`
}

type certificateRetry struct {
	Failures    int       `json:"failures"`
	NextAttempt time.Time `json:"next_attempt"`
	LastError   string    `json:"last_error"`
}

type managedCertificate struct {
	Certificate []byte
	PrivateKey  []byte
	Metadata    certificateMetadata
	Leaf        *x509.Certificate
}

type issuedCertificate struct {
	Certificate []byte
	PrivateKey  []byte
	Metadata    certificateMetadata
}

type certificateStatus struct {
	Domains        []string
	EarliestExpiry time.Time
	Warning        string
}

type certificateIssuer interface {
	Issue(certificateRequirement, *managedCertificate) (*issuedCertificate, error)
}

type certificateManager struct {
	root   string
	issuer certificateIssuer
	now    func() time.Time
}

type legoUser struct {
	Email        string
	Registration *registration.Resource
	PrivateKey   crypto.PrivateKey
	accountDir   string
}

func (u *legoUser) GetEmail() string                        { return u.Email }
func (u *legoUser) GetRegistration() *registration.Resource { return u.Registration }
func (u *legoUser) GetPrivateKey() crypto.PrivateKey        { return u.PrivateKey }

type legoCertificateIssuer struct{ accountRoot string }

func newCertificateManager(root string) *certificateManager {
	return &certificateManager{root: root, issuer: &legoCertificateIssuer{accountRoot: filepath.Join(root, "accounts")}, now: time.Now}
}

func (a *agent) certificateManagerForConfig() *certificateManager {
	if a.certManager == nil {
		a.certManager = newCertificateManager(filepath.Join(a.config.StatePath, "certificates"))
	}
	return a.certManager
}

func (a *agent) setCertificateStatus(status certificateStatus, certificateErr error) {
	a.certificateStatus = status
	messages := make([]string, 0, 2)
	if status.Warning != "" {
		messages = append(messages, status.Warning)
	}
	if certificateErr != nil {
		messages = append(messages, certificateErr.Error())
	}
	a.lastCertificateError = strings.Join(messages, "; ")
}

func (a *agent) maintainCertificates() (bool, certificateStatus, error) {
	path := filepath.Join(a.config.StatePath, "current", "certificates.json")
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, certificateStatus{}, nil
	}
	if err != nil {
		return false, certificateStatus{}, fmt.Errorf("read certificate requirements: %w", err)
	}
	var requirements []certificateRequirement
	if err := json.Unmarshal(data, &requirements); err != nil {
		return false, certificateStatus{}, fmt.Errorf("parse certificate requirements: %w", err)
	}
	return a.certificateManagerForConfig().Ensure(requirements)
}

func certificateDomainRoot(root, domain string) string { return filepath.Join(root, domain) }

func certificateCurrentRoot(root, domain string) string {
	return filepath.Join(certificateDomainRoot(root, domain), "current")
}

func (m *certificateManager) Ensure(requirements []certificateRequirement) (bool, certificateStatus, error) {
	status := certificateStatus{}
	unique := make(map[string]certificateRequirement)
	for _, requirement := range requirements {
		requirement.Domain = strings.ToLower(strings.TrimSpace(requirement.Domain))
		requirement.Email = strings.ToLower(strings.TrimSpace(requirement.Email))
		if len(requirement.Domain) > 253 || !managedDomainPattern.MatchString(requirement.Domain) || !strings.Contains(requirement.Email, "@") || len(requirement.Email) > 254 {
			return false, status, fmt.Errorf("invalid managed certificate requirement for %q", requirement.Domain)
		}
		if existing, ok := unique[requirement.Domain]; ok && existing.Email != requirement.Email {
			return false, status, fmt.Errorf("certificate domain %s has conflicting ACME emails", requirement.Domain)
		}
		unique[requirement.Domain] = requirement
	}
	domains := make([]string, 0, len(unique))
	for domain := range unique {
		domains = append(domains, domain)
	}
	sort.Strings(domains)
	status.Domains = domains
	changed := false
	warnings := make([]string, 0)
	fatalErrors := make([]string, 0)
	for _, domain := range domains {
		requirement := unique[domain]
		current, currentErr := loadManagedCertificate(m.root, domain)
		valid := currentErr == nil && current.Leaf.NotAfter.After(m.now()) && current.Leaf.VerifyHostname(domain) == nil
		if valid {
			if current.Leaf.NotAfter.Sub(m.now()) > certificateRenewBefore {
				status.EarliestExpiry = earlierCertificateExpiry(status.EarliestExpiry, current.Leaf.NotAfter)
				continue
			}
		}
		if retry, ok := loadCertificateRetry(m.root, domain); ok && m.now().Before(retry.NextAttempt) {
			message := fmt.Sprintf("%s ACME retry deferred until %s: %s", domain, retry.NextAttempt.UTC().Format(time.RFC3339), retry.LastError)
			if valid {
				warnings = append(warnings, message)
				status.EarliestExpiry = earlierCertificateExpiry(status.EarliestExpiry, current.Leaf.NotAfter)
			} else {
				fatalErrors = append(fatalErrors, message)
			}
			continue
		}
		issued, err := m.issuer.Issue(requirement, func() *managedCertificate {
			if valid {
				return current
			}
			return nil
		}())
		if err != nil {
			retry := recordCertificateFailure(m.root, domain, err, m.now())
			message := fmt.Sprintf("%s ACME failed; next retry %s: %v", domain, retry.NextAttempt.UTC().Format(time.RFC3339), err)
			if valid {
				warnings = append(warnings, message)
				status.EarliestExpiry = earlierCertificateExpiry(status.EarliestExpiry, current.Leaf.NotAfter)
			} else {
				fatalErrors = append(fatalErrors, message)
			}
			continue
		}
		leaf, err := validateCertificatePair(domain, issued.Certificate, issued.PrivateKey)
		if err == nil && (leaf.NotAfter.After(m.now()) == false || leaf.NotBefore.After(m.now().Add(5*time.Minute))) {
			err = errors.New("issued certificate is not currently valid")
		}
		if err == nil {
			err = saveManagedCertificate(m.root, domain, issued)
		}
		if err != nil {
			retry := recordCertificateFailure(m.root, domain, err, m.now())
			message := fmt.Sprintf("%s certificate activation failed; next retry %s: %v", domain, retry.NextAttempt.UTC().Format(time.RFC3339), err)
			if valid {
				warnings = append(warnings, message)
				status.EarliestExpiry = earlierCertificateExpiry(status.EarliestExpiry, current.Leaf.NotAfter)
			} else {
				fatalErrors = append(fatalErrors, message)
			}
			continue
		}
		_ = os.Remove(filepath.Join(certificateDomainRoot(m.root, domain), "retry.json"))
		changed = true
		status.EarliestExpiry = earlierCertificateExpiry(status.EarliestExpiry, leaf.NotAfter)
	}
	status.Warning = strings.Join(warnings, "; ")
	if len(fatalErrors) > 0 {
		return changed, status, errors.New(strings.Join(fatalErrors, "; "))
	}
	return changed, status, nil
}

func earlierCertificateExpiry(current, candidate time.Time) time.Time {
	if current.IsZero() || candidate.Before(current) {
		return candidate
	}
	return current
}

func validateCertificatePair(domain string, certificatePEM, privateKeyPEM []byte) (*x509.Certificate, error) {
	pair, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil {
		return nil, err
	}
	if len(pair.Certificate) == 0 {
		return nil, errors.New("certificate chain is empty")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, err
	}
	if err := leaf.VerifyHostname(domain); err != nil {
		return nil, err
	}
	return leaf, nil
}

func loadManagedCertificate(root, domain string) (*managedCertificate, error) {
	current := certificateCurrentRoot(root, domain)
	certificatePEM, err := os.ReadFile(filepath.Join(current, "fullchain.pem"))
	if err != nil {
		return nil, err
	}
	privateKeyPEM, err := os.ReadFile(filepath.Join(current, "privatekey.pem"))
	if err != nil {
		return nil, err
	}
	leaf, err := validateCertificatePair(domain, certificatePEM, privateKeyPEM)
	if err != nil {
		return nil, err
	}
	metadata := certificateMetadata{Domain: domain}
	if data, readErr := os.ReadFile(filepath.Join(current, "metadata.json")); readErr == nil {
		_ = json.Unmarshal(data, &metadata)
	}
	return &managedCertificate{Certificate: certificatePEM, PrivateKey: privateKeyPEM, Metadata: metadata, Leaf: leaf}, nil
}

func saveManagedCertificate(root, domain string, issued *issuedCertificate) error {
	domainRoot := certificateDomainRoot(root, domain)
	releaseName := fmt.Sprintf("%d", time.Now().UTC().UnixNano())
	releaseRoot := filepath.Join(domainRoot, "releases", releaseName)
	if err := os.MkdirAll(releaseRoot, 0700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(releaseRoot, "privatekey.pem"), issued.PrivateKey, 0600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(releaseRoot, "fullchain.pem"), issued.Certificate, 0644); err != nil {
		return err
	}
	if err := writeJSONAtomic(filepath.Join(releaseRoot, "metadata.json"), issued.Metadata, 0600); err != nil {
		return err
	}
	if err := atomicSymlink(releaseRoot, filepath.Join(domainRoot, "current")); err != nil {
		return err
	}
	return pruneCertificateReleases(domainRoot, releaseRoot)
}

func pruneCertificateReleases(domainRoot, current string) error {
	entries, err := os.ReadDir(filepath.Join(domainRoot, "releases"))
	if err != nil {
		return err
	}
	type release struct {
		path string
		mod  time.Time
	}
	releases := make([]release, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		info, infoErr := entry.Info()
		if infoErr == nil {
			releases = append(releases, release{path: filepath.Join(domainRoot, "releases", entry.Name()), mod: info.ModTime()})
		}
	}
	sort.Slice(releases, func(i, j int) bool { return releases[i].mod.After(releases[j].mod) })
	if len(releases) <= 2 {
		return nil
	}
	for _, item := range releases[2:] {
		if filepath.Clean(item.path) != filepath.Clean(current) {
			_ = os.RemoveAll(item.path)
		}
	}
	return nil
}

func loadCertificateRetry(root, domain string) (certificateRetry, bool) {
	var retry certificateRetry
	data, err := os.ReadFile(filepath.Join(certificateDomainRoot(root, domain), "retry.json"))
	if err != nil || json.Unmarshal(data, &retry) != nil {
		return certificateRetry{}, false
	}
	return retry, true
}

func recordCertificateFailure(root, domain string, issueErr error, now time.Time) certificateRetry {
	retry, _ := loadCertificateRetry(root, domain)
	retry.Failures++
	shift := retry.Failures - 1
	if shift > 6 {
		shift = 6
	}
	delay := 5 * time.Minute * time.Duration(1<<shift)
	if delay > 6*time.Hour {
		delay = 6 * time.Hour
	}
	retry.NextAttempt = now.Add(delay)
	retry.LastError = issueErr.Error()
	_ = writeJSONAtomic(filepath.Join(certificateDomainRoot(root, domain), "retry.json"), retry, 0600)
	return retry
}

func (i *legoCertificateIssuer) Issue(requirement certificateRequirement, current *managedCertificate) (*issuedCertificate, error) {
	user, err := loadOrCreateLegoUser(i.accountRoot, requirement.Email)
	if err != nil {
		return nil, err
	}
	configuration := lego.NewConfig(user)
	configuration.Certificate.KeyType = certcrypto.EC256
	client, err := lego.NewClient(configuration)
	if err != nil {
		return nil, err
	}
	if err := client.Challenge.SetHTTP01Provider(http01.NewProviderServer("", "80")); err != nil {
		return nil, err
	}
	if user.Registration == nil {
		user.Registration, err = client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return nil, err
		}
		if err := writeJSONAtomic(filepath.Join(user.accountDir, "registration.json"), user.Registration, 0600); err != nil {
			return nil, err
		}
	}
	var resource *certificate.Resource
	if current != nil && current.Metadata.CertURL != "" {
		resource, err = client.Certificate.Renew(certificate.Resource{
			Domain: current.Metadata.Domain, CertURL: current.Metadata.CertURL, CertStableURL: current.Metadata.CertStableURL,
			Certificate: current.Certificate, PrivateKey: current.PrivateKey,
		}, true, false, "")
	} else {
		resource, err = client.Certificate.Obtain(certificate.ObtainRequest{Domains: []string{requirement.Domain}, Bundle: true})
	}
	if err != nil {
		return nil, err
	}
	return &issuedCertificate{
		Certificate: resource.Certificate,
		PrivateKey:  resource.PrivateKey,
		Metadata: certificateMetadata{
			Domain: requirement.Domain, CertURL: resource.CertURL, CertStableURL: resource.CertStableURL,
		},
	}, nil
}

func loadOrCreateLegoUser(accountRoot, email string) (*legoUser, error) {
	digest := sha256.Sum256([]byte(strings.ToLower(email)))
	accountDir := filepath.Join(accountRoot, hex.EncodeToString(digest[:16]))
	if err := os.MkdirAll(accountDir, 0700); err != nil {
		return nil, err
	}
	keyPath := filepath.Join(accountDir, "privatekey.pem")
	privateKey, err := loadOrCreateAccountKey(keyPath)
	if err != nil {
		return nil, err
	}
	user := &legoUser{Email: email, PrivateKey: privateKey, accountDir: accountDir}
	if data, readErr := os.ReadFile(filepath.Join(accountDir, "registration.json")); readErr == nil {
		var resource registration.Resource
		if json.Unmarshal(data, &resource) == nil && resource.URI != "" {
			user.Registration = &resource
		}
	}
	return user, nil
}

func loadOrCreateAccountKey(path string) (*ecdsa.PrivateKey, error) {
	if data, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, errors.New("ACME account private key is invalid")
		}
		return x509.ParseECPrivateKey(block.Bytes)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	encoded, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: encoded}), 0600); err != nil {
		return nil, err
	}
	return privateKey, nil
}
