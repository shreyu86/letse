package letse

import (
	"crypto/x509"
	"errors"
	"log"

	"github.com/ericchiang/letsencrypt"
)

const (
	prodURL = "https://acme-v01.api.letsencrypt.org/directory"
	stagURL = "https://acme-staging.api.letsencrypt.org/directory"
)

var (
	// ErrCreatingLEClient is returned when it is unable to initialize LE's client.
	ErrCreatingLEClient = errors.New("error creating LetsEncrypt client")
	// ErrRequestingAuthz is returned when requesting DNS authorization from LE fails.
	ErrRequestingAuthz = errors.New("error requesting DNS authorization challenge from LetsEncrypt servers")
	// ErrUnsupportedChallenges ...
	ErrUnsupportedChallenges = errors.New("LetsEncrypt servers sent unsupported challenges")
	// ErrRetrievingChallengeToken ...
	ErrRetrievingChallengeToken = errors.New("error retrieving LetsEncrypt challenge token")
	// ErrCreatingDNSTXTRecord ...
	ErrCreatingDNSTXTRecord = errors.New("unable to create DNS TXT record in DNS provider service")
	// ErrNotifyingChallengeReadiness ...
	ErrNotifyingChallengeReadiness = errors.New("error notifying LetsEncrypt servers that challenge is ready to be verified")
	// ErrGettingCertificate ...
	ErrGettingCertificate = errors.New("error getting new certificate from LetsEncrypt servers")
	// ErrRegisteringAccountKey ...
	ErrRegisteringAccountKey = errors.New("error registering account key with LetsEncrypt servers")
)

// supportedChallenges lists challenges supported by this LetsEncrypt client.
var supportedChallenges = []string{
	letsencrypt.ChallengeDNS,
}

// DNSProvider is the interface to implement for each DNS Provider supported.
type DNSProvider interface {
	AddTXTRecord(name, value string) error
	RemoveTXTRecord(name string) error
}

// Client represents an opinionated LetsEncrypt client that only completes
// DNS challenges.
type Client struct {
	accountKey interface{}
	lc         *letsencrypt.Client
	la         letsencrypt.Authorization
}

// NewClient creates a new instance of Letse's LetsEncrypt client. Allowing
// to use LetsEncrypt staging or production servers.
func NewClient(accountKey interface{}, dryRun bool) (*Client, error) {
	var lc *letsencrypt.Client
	var err error
	if dryRun {
		lc, err = letsencrypt.NewClient(stagURL)
	} else {
		lc, err = letsencrypt.NewClient(prodURL)
	}

	if err != nil {
		log.Printf(`lv=err msg=%q le-err=%q`, ErrCreatingLEClient, err)
		return nil, ErrCreatingLEClient
	}

	return &Client{
		lc:         lc,
		accountKey: accountKey,
	}, nil
}

// Register registers account key with LetsEncrypt servers.
func (c *Client) Register() error {
	_, err := c.lc.NewRegistration(c.accountKey)
	if err != nil {
		log.Printf(`lv=err msg=%q le-err=%q`, ErrRegisteringAccountKey, err)
		return ErrRegisteringAccountKey
	}
	return err
}

// RequestAuthz requests authorization from LetsEncrypt servers to issue
// operations on the certificate of the given domain name.
func (c *Client) RequestAuthz(domain string) error {
	auth, _, err := c.lc.NewAuthorization(c.accountKey, "dns", domain)
	if err != nil {
		log.Printf(`lv=err msg=%q le-err=%q`, ErrRequestingAuthz, err)
		return ErrRequestingAuthz
	}
	c.la = auth
	return nil
}

// CompleteChallenge completes LetsEncrypt DNS challenge using the passed DNS
// provider.
func (c *Client) CompleteChallenge(provider DNSProvider) error {
	chals := c.la.Combinations(supportedChallenges...)
	if len(chals) == 0 {
		log.Printf(`lv=err msg=%q challenges=%+v`, ErrUnsupportedChallenges, chals)
		return ErrUnsupportedChallenges
	}

	chal := chals[0][0]
	subdomain, token, err := chal.DNS(c.accountKey)
	if err != nil {
		log.Printf(`lv=err msg=%q le-err=%q`, ErrRetrievingChallengeToken, err)
		return ErrRetrievingChallengeToken
	}

	if err := provider.AddTXTRecord(subdomain, token); err != nil {
		log.Printf(`lv=err msg=%q le-err=%q`, ErrCreatingDNSTXTRecord, err)
		return ErrCreatingDNSTXTRecord
	}
	defer func() {
		err := provider.RemoveTXTRecord(subdomain)
		if err != nil {
			log.Printf(`lv=warn msg="error deleting TXT record from DNS provider" le-err=%q`, err)
		}
	}()

	// Notifies LetsEncrypt servers that the challenge is ready to be verified.
	if err := c.lc.ChallengeReady(c.accountKey, chal); err != nil {
		log.Printf(`lv=err msg=%q le-err=%q`, ErrNotifyingChallengeReadiness, err)
		return ErrNotifyingChallengeReadiness
	}
	return nil
}

// NewCert requests a new certificate to LetsEncrypt servers.
func (c *Client) NewCert(csr *x509.CertificateRequest) (*x509.Certificate, error) {
	cert, err := c.lc.NewCertificate(c.accountKey, csr)
	if err != nil {
		log.Printf(`lv=err msg=%q le-err=%q`, ErrGettingCertificate, err)
		return nil, ErrGettingCertificate
	}
	return cert.Certificate, nil
}

// RevokeCert ...
func (c *Client) RevokeCert(cert *x509.Certificate) error {
	return nil
}

// RenewCert ...
func (c *Client) RenewCert(cert *x509.Certificate) error {
	return nil
}
