package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

	"github.com/c4milo/letse/route53"
	"github.com/docopt/docopt-go"
	"github.com/ericchiang/letsencrypt"
)

// DNSProvider is the interface to implement for each DNS Provider supported.
type DNSProvider interface {
	AddTXTRecord(name, value string) error
	RemoveTXTRecord(name string) error
}

var (
	// Version is injected in compile time
	Version string
	// supportedChallenges lists challenges supported by this LetsEncrypt client.
	supportedChallenges = []string{
		letsencrypt.ChallengeDNS,
	}
)

const (
	prodURL = "https://acme-v01.api.letsencrypt.org/directory"
	stagURL = "https://acme-staging.api.letsencrypt.org/directory"
)

var usage = `
Simple DNS based LetsEncrypt CLI ` + Version + `.

Usage:
  letse new <domain> -k <account-key> -p <dns-provider> -t <key-type> -o <output-dir>
  letse renew <cert-file> -f
  letse revoke <cert-file> -k <account-key>
  letse keygen -t <key-type>

Options:
-k       LetsEncrypt Account Key.
-p       DNS Provider.
-t       Key type, either rsa or ecdsa. [default: ecdsa].
-o       Directory where to output certificate and certificate private key. [default: .].
-f       Forces a certificate renewal
-dry-run Uses LetsEncrypt staging server instead.

DNS Providers:
* r53: AWS Route53

`

func main() {
	args, _ := docopt.Parse(usage, nil, true, "Simple LetsEncrypt CLI", false)
	if args["new"].(bool) {
		new(args)
	} else if args["renew"].(bool) {
		renew(args)
	} else if args["revoke"].(bool) {
		revoke(args)
	} else if args["keygen"].(bool) {
		keygen(args)
	} else {
		fmt.Println(usage)
	}
}

func new(args map[string]interface{}) {
	var cli *letsencrypt.Client
	var err error
	if args["-dry-run"].(bool) {
		cli, err = letsencrypt.NewClient(stagURL)
	} else {
		cli, err = letsencrypt.NewClient(prodURL)
	}

	if err != nil {
		log.Fatalf("failed to create client: %s\n", err)
	}

	accountKey, err := parsePEMPrivateKey(args["account-key"].(string))
	if err != nil {
		log.Fatalf("unable to parse PEM encoded account key: %s\n", err)
	}

	domain := args["domain"].(string)

	auth, _, err := cli.NewAuthorization(accountKey, "dns", domain)
	if err != nil {
		log.Fatal(err)
	}

	chals := auth.Combinations(supportedChallenges...)
	if len(chals) == 0 {
		log.Fatal("no supported challenge combinations")
	}

	chal := chals[0][0]
	subdomain, token, err := chal.DNS(accountKey)
	if err != nil {
		log.Fatal(err)
	}

	var p DNSProvider
	switch args["-p"].(string) {
	case "r53":
		p = route53.New(domain)
	default:
		log.Fatalf("DNS provider not supported: %s\n", args["-p"].(string))
	}

	if err := p.AddTXTRecord(subdomain, token); err != nil {
		log.Fatalf("error creating Route53 record %s, with value %s", subdomain, token)
	}
	defer p.RemoveTXTRecord(subdomain)

	// Notifies LetsEncrypt servers that the challenge is ready to be verified.
	if err := cli.ChallengeReady(accountKey, chal); err != nil {
		log.Fatal(err)
	}
	// create a certificate request
	keyType := args["-t"].(string)
	csr, certKey, err := newCertificateRequest(domain, keyType)
	if err != nil {
		log.Fatal(err)
	}

	// Request a certificate for your domain
	cert, err := cli.NewCertificate(accountKey, csr)
	if err != nil {
		log.Fatal(err)
	}

	outputFile := filepath.Join(args["-o"].(string), domain)
	if err := storePrivateKey(certKey, outputFile+".pk"); err != nil {
		log.Fatal("unable to store certificate private key: ", err)
	}

	if err := storeCertificate(cert.Certificate, accountKey, outputFile+".cert"); err != nil {
		log.Fatal("unable to store certificate: ", err)
	}
}

func parsePEMPrivateKey(path string) (interface{}, error) {
	accountKeyPEM, err := ioutil.ReadFile(path)
	if err != nil {
		log.Fatal("failed to read account key:", err)
	}

	block, _ := pem.Decode(accountKeyPEM)
	if block == nil {
		log.Fatal("bad account key data, not PEM encoded:", err)
	}

	if block.Type == "RSA PRIVATE KEY" {
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	}

	return x509.ParseECPrivateKey(block.Bytes)
}

// storePrivateKey persist private key to disk.
func storePrivateKey(pk interface{}, fpath string) error {
	pkFile, err := os.Create(fpath)
	if err != nil {
		return err
	}

	defer func() {
		if err := pkFile.Close(); err != nil {
			log.Printf(`lv=err msg="Error closing private key file" err=%s`, err)
		}
	}()

	var pkPEM *pem.Block
	switch k := pk.(type) {
	case *rsa.PrivateKey:
		pkPEM = &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return fmt.Errorf("Unable to marshal ECDSA private key: %v", err)
		}
		pkPEM = &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	}

	return pem.Encode(pkFile, pkPEM)
}

func storeCertificate(cert *x509.Certificate, pk interface{}, fpath string) error {
	certFile, err := os.Create(fpath)
	if err != nil {
		return err
	}

	defer func() {
		if err := certFile.Close(); err != nil {
			log.Fatalf(`lv=err msg="Error closing certificate file" err=%s`, err)
		}
	}()

	certPEM := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}

	return pem.Encode(certFile, certPEM)
}

func newCertificateRequest(domain, keyType string) (*x509.CertificateRequest, interface{}, error) {
	var certKey interface{}
	var err error
	template := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: domain},
		DNSNames: []string{domain},
	}

	switch keyType {
	case "rsa":
		certKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, nil, err
		}
		template.SignatureAlgorithm = x509.SHA256WithRSA
		template.PublicKeyAlgorithm = x509.RSA
		template.PublicKey = &certKey.(*rsa.PrivateKey).PublicKey
	case "ecdsa":
		certKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		template.SignatureAlgorithm = x509.ECDSAWithSHA256
		template.PublicKeyAlgorithm = x509.ECDSA
		template.PublicKey = &certKey.(*ecdsa.PrivateKey).PublicKey
	default:
		log.Fatalf("invalid key type: %s\n", keyType)
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, certKey)
	if err != nil {
		return nil, nil, err
	}

	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, nil, err
	}
	return csr, certKey, nil
}

func renew(args map[string]interface{}) {

}

func revoke(args map[string]interface{}) {

}

func keygen(args map[string]interface{}) {

}
