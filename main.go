package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
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
Simple DNS based LetsEncrypt CLI.

Usage:
  letse new <domain> -a <account-key> [-p dns-provider] [-k key-type] [-o output-dir]
  letse renew <cert-file> -f
  letse revoke <cert-file> -a <account-key>
  letse keygen [-k key-type] [-b bit-size] [-o output-dir]

Options:
  -a, --account-key=<account-key>    LetsEncrypt Account Key.
  -p, --provider=<provider>          DNS Provider. [default: r53].
  -k, --key-type=<key-type>          Key type, either rsa or ecdsa. [default: ecdsa].
  -o, --output=<output>              Directory where to output secrets. [default: .].
  -f, --force                        Forces a certificate renewal.
  -b, --bit-size=<bit-size>          Bit size for the key. Defaults to 256 for ECDSA or 2048 for RSA.
  -d, --dry-run                      Uses LetsEncrypt staging server instead.

DNS Providers:
  * r53: AWS Route53
`

func main() {
	args, err := docopt.Parse(usage, nil, true, `Simple DNS based LetsEncrypt CLI `+Version, false)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	if len(args) == 0 {
		fmt.Println(usage)
		os.Exit(1)
	}

	fmt.Println(args)
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
	if args["--dry-run"].(bool) {
		cli, err = letsencrypt.NewClient(stagURL)
	} else {
		cli, err = letsencrypt.NewClient(prodURL)
	}

	if err != nil {
		log.Fatalf("failed to create client: %s", err)
	}

	accountKey, err := parsePEMPrivateKey(args["account-key"].(string))
	if err != nil {
		log.Fatalf("unable to parse PEM encoded account key: %s", err)
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
	switch args["--provider"].(string) {
	case "r53":
		p = route53.New(domain)
	default:
		log.Fatalf("DNS provider not supported: %s", args["--provider"].(string))
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
	keyType := args["--key-type"].(string)
	csr, certKey, err := newCertificateRequest(domain, keyType)
	if err != nil {
		log.Fatal(err)
	}

	// Request a certificate for your domain
	cert, err := cli.NewCertificate(accountKey, csr)
	if err != nil {
		log.Fatal(err)
	}

	outputFile := filepath.Join(args["--output"].(string), domain)
	if err := storePrivateKey(certKey, outputFile+".key"); err != nil {
		log.Fatalf("unable to store certificate private key: %s", err)
	}

	if err := storeCertificate(cert.Certificate, accountKey, outputFile+".crt"); err != nil {
		log.Fatalf("unable to store certificate: %s", err)
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
	if _, err := os.Stat(fpath); err == nil {
		return fmt.Errorf("a private key already exist: %q", fpath)
	}

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

		// Go's standard library is encoding the curve oid within the public key.
		// https://golang.org/src/crypto/x509/x509.go#L53
		// We are not encoding a PEM block for EC PARAMETERS yet, until a specific
		// use case involving OpenSSL requires us to do such thing.
		// See also: http://security.stackexchange.com/questions/29778/why-does-openssl-writes-ec-parameters-when-generating-private-key
		pkPEM = &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	}

	return pem.Encode(pkFile, pkPEM)
}

// storePublicKey persist to disk the public key associated to the given private key.
func storePublicKey(pk interface{}, fpath string) error {
	if _, err := os.Stat(fpath); err == nil {
		return fmt.Errorf("a public key already exist: %q", fpath)
	}

	pkFile, err := os.Create(fpath)
	if err != nil {
		return err
	}

	defer func() {
		if err := pkFile.Close(); err != nil {
			log.Printf(`lv=err msg="Error closing public key file" err=%s`, err)
		}
	}()

	var pkPEM *pem.Block
	switch k := pk.(type) {
	case *rsa.PrivateKey:
		b, err := x509.MarshalPKIXPublicKey(k.Public())
		if err != nil {
			return fmt.Errorf("Unable to marshal RSA public key: %v", err)
		}
		pkPEM = &pem.Block{Type: "RSA PUBLIC KEY", Bytes: b}
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalPKIXPublicKey(k.Public())
		if err != nil {
			return fmt.Errorf("Unable to marshal ECDSA public key: %v", err)
		}
		pkPEM = &pem.Block{Type: "EC PUBLIC KEY", Bytes: b}
	default:
		return fmt.Errorf("unsupported cryptographic key")
	}

	return pem.Encode(pkFile, pkPEM)
}

func storeCertificate(cert *x509.Certificate, pk interface{}, fpath string) error {
	if _, err := os.Stat(fpath); err == nil {
		return fmt.Errorf("a certificate already exist: %q", fpath)
	}

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
	// Check expiration date, it it is within 45 days, renew it.
	// Otherwise, do not re-new it unless it is forced by user
}

func revoke(args map[string]interface{}) {

}

func keygen(args map[string]interface{}) {
	var key interface{}
	var err error

	keyType := args["--key-type"].(string)
	var bitSize int

	bs := args["--bit-size"]
	if bs != nil {
		bitSize = bs.(int)
	}

	switch keyType {
	case "rsa":
		if bitSize == 0 {
			bitSize = 2048
		}

		key, err = rsa.GenerateKey(rand.Reader, bitSize)
	case "ecdsa":
		if bitSize == 0 {
			bitSize = 256
		}

		switch bitSize {
		case 224, 256:
			key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		case 384:
			key, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		case 521:
			key, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		default:
			err = errors.New("unknown elliptic curve")
		}
	}

	if err != nil {
		log.Fatalf("error generating key pair: %s", err)
	}

	outputDir := args["--output"].(string)
	outputFile := filepath.Join(outputDir, "private_key.pem")
	if err := storePrivateKey(key, outputFile); err != nil {
		log.Fatalf("unable to store private key: %s", err)
	}

	outputFile = filepath.Join(outputDir, "public_key.pem")
	if err := storePublicKey(key, outputFile); err != nil {
		log.Fatalf("unable to store public key: %s", err)
	}
}
