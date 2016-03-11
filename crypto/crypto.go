package crypto

import (
	"crypto"
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
func Keygen(ktype string, size int) (crypto.PrivateKey, error) {
	var key crypto.PrivateKey
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

		var curve elliptic.Curve
		switch size {
		case 224, 256:
			curve = elliptic.P256()
		case 384:
			curve = elliptic.P384()
		case 521:
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("invalid elliptic curve: %d. Correct values are: 256, 384 or 521", size)
		}
		key, err = ecdsa.GenerateKey(curve, rand.Reader)
	}

	return key, err
}

// WritePrivateKey persist private key to disk.
func WritePrivateKey(pk crypto.PrivateKey, dst io.Writer) error {
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
func WritePublicKey(pk crypto.PrivateKey, dst io.Writer) error {
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
func WriteCertificate(cert *x509.Certificate, dst io.Writer) error {
	certPEM := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}

	return pem.Encode(dst, certPEM)
}

// NewCertificateRequest generates a new certificate signing requests for a given domain.
func NewCertificateRequest(domain, keyType string, bitSize int) (*x509.CertificateRequest, crypto.PrivateKey, error) {
	var certKey crypto.PrivateKey
	var err error
	template := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: domain},
		DNSNames: []string{domain},
	}

	switch keyType {
	case "rsa":
		if bitSize == 0 {
			bitSize = 2048
		}

		switch bitSize {
		case 2048:
			template.SignatureAlgorithm = x509.SHA256WithRSA
		case 3072:
			template.SignatureAlgorithm = x509.SHA384WithRSA
		case 4096:
			template.SignatureAlgorithm = x509.SHA512WithRSA
		default:
			log.Fatalf("inrecognized RSA key size: %d\n", bitSize)
		}

		certKey, err = rsa.GenerateKey(rand.Reader, bitSize)
		if err != nil {
			return nil, nil, err
		}

		template.PublicKeyAlgorithm = x509.RSA
		template.PublicKey = &certKey.(*rsa.PrivateKey).PublicKey
	case "ecdsa":
		if bitSize == 0 {
			bitSize = 256
		}

		var curve elliptic.Curve
		switch bitSize {
		case 224, 256:
			curve = elliptic.P256()
			template.SignatureAlgorithm = x509.ECDSAWithSHA256
		case 384:
			curve = elliptic.P384()
			template.SignatureAlgorithm = x509.ECDSAWithSHA384
		case 521:
			curve = elliptic.P521()
			template.SignatureAlgorithm = x509.ECDSAWithSHA512
		default:
			return nil, nil, ErrUnknownEllipticCurve
		}

		certKey, err = ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return nil, nil, err
		}
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
func ParsePEMPrivateKey(path string) (crypto.PrivateKey, error) {
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
