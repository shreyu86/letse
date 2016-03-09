package crypto

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
	"io"
	"io/ioutil"
	"log"
)

// ErrUnknownEllipticCurve is returned when a not supported Elliptic curve bit
// size is received during call to Keygen.
var ErrUnknownEllipticCurve = errors.New("unknown elliptic curve")

// Keygen generates a key pair using RSA or ECDSA.
func Keygen(ktype string, size int) (interface{}, error) {
	var key interface{}
	var err error

	switch ktype {
	case "rsa":
		if size == 0 {
			size = 2048
		}

		key, err = rsa.GenerateKey(rand.Reader, size)
	case "ecdsa":
		if size == 0 {
			size = 256
		}

		switch size {
		case 224, 256:
			key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		case 384:
			key, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		case 521:
			key, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		default:
			err = ErrUnknownEllipticCurve
		}
	}

	return key, err
}

// WritePrivateKey persist private key to disk.
func WritePrivateKey(pk interface{}, dst io.Writer) error {
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

	return pem.Encode(dst, pkPEM)
}

// WritePublicKey persist to disk the public key associated to the given private key.
func WritePublicKey(pk interface{}, dst io.Writer) error {
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

	return pem.Encode(dst, pkPEM)
}

// WriteCertificate PEM encodes and writes the given certificate to the writer.
func WriteCertificate(cert *x509.Certificate, pk interface{}, dst io.Writer) error {
	certPEM := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}

	return pem.Encode(dst, certPEM)
}

// NewCertificateRequest generates a new certificate signing requests for a given domain.
func NewCertificateRequest(domain, keyType string, bitSize int) (*x509.CertificateRequest, interface{}, error) {
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

// ParsePEMPrivateKey takes the path to a private key in disk, decodes it and
// returns a Go instance of the key.
func ParsePEMPrivateKey(path string) (interface{}, error) {
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
