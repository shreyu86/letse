package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	"github.com/shreyu86/letse"
	"github.com/shreyu86/letse/crypto"
	"github.com/shreyu86/letse/route53"
	"github.com/docopt/docopt-go"
)

var (
	// Version is injected in compile time
	Version string
)

var usage = `
Simple DNS based LetsEncrypt CLI.

Usage:
  letse new <domain> -a <account-key> [-p dns-provider] [-k key-type] [-b bit-size] [-o output-dir] [--dry-run]
  letse renew <cert-file> [--if-expires-within duration]
  letse revoke <cert-file> -a <account-key>
  letse keygen [-k key-type] [-b bit-size] [-o output-dir]
  letse server -c <cert> -f <cert-key>

Options:
  -a, --account-key=<account-key>    LetsEncrypt Account Key. When requesting a new certificate, it will be registered if it is not.
  -p, --provider=<provider>          DNS Provider. [default: r53].
  -k, --key-type=<key-type>          Key type, either rsa or ecdsa. [default: ecdsa].
  -o, --output=<output>              Directory where to output secrets. [default: .].
  -b, --bit-size=<bit-size>          Bit size for the key. Defaults to 256 for ECDSA or 2048 for RSA.
  -i, --if-expires-within=<period>   Renew certificate only if it expires within the given time period.
  -d, --dry-run                      Uses LetsEncrypt staging server instead.
  -c, --cert=<cert>                  x509 certificate to load on the HTTPS server.
  -f, --cert-key=<cert-key>          x509 certificate private key to load on the HTTPS server.

DNS Providers:
  * r53: AWS Route53
`

func init() {
	log.SetFlags(0)
}

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

	//fmt.Println(args)
	if args["new"].(bool) {
		new(args)
	} else if args["renew"].(bool) {
		renew(args)
	} else if args["revoke"].(bool) {
		revoke(args)
	} else if args["keygen"].(bool) {
		keygen(args)
	} else if args["server"].(bool) {
		server(args)
	} else {
		fmt.Println(usage)
	}
}

func new(args map[string]interface{}) {
	accountKey, err := crypto.ParsePEMPrivateKey(args["--account-key"].(string))
	if err != nil {
		log.Fatalf("unable to parse PEM encoded account key: %s", err)
	}

	cli, err := letse.NewClient(accountKey, args["--dry-run"].(bool))
	if err != nil {
		log.Fatalf("failed to create client: %s", err)
	}

	if err := cli.Register(); err != nil {
		log.Fatalln(err)
	}

	domain := args["<domain>"].(string)
	if err := cli.RequestAuthz(domain); err != nil {
		log.Fatalln(err)
	}

	var p letse.DNSProvider
	switch args["--provider"].(string) {
	case "r53":
		p = route53.New(domain)
	default:
		log.Fatalf("DNS provider not supported: %s", args["--provider"].(string))
	}

	if err := cli.CompleteChallenge(p); err != nil {
		log.Fatalf("failed to complete LetsEncrypt challenge: %s", err)
	}

	// create a certificate request
	keyType := args["--key-type"].(string)
	var bitSize int
	if args["--bit-size"] != nil {
		bitSize = args["--bit-size"].(int)
	}

	csr, certKey, err := crypto.NewCertificateRequest(domain, keyType, bitSize)
	if err != nil {
		log.Fatal(err)
	}

	// Request a certificate for your domain
	cert, err := cli.NewCert(csr)
	if err != nil {
		log.Fatal(err)
	}

	outputFile := filepath.Join(args["--output"].(string), domain)
	keyPath := outputFile + ".key"
	if _, err := os.Stat(keyPath); err == nil {
		log.Fatalf("a private key already exist: %q", keyPath)
	}

	keyFile, err := os.Create(keyPath)
	if err != nil {
		log.Fatalln(err)
	}

	defer func() {
		if err := keyFile.Close(); err != nil {
			log.Fatalf(`lv=err msg="Error closing private key file" err=%s`, err)
		}
	}()

	if err = crypto.WritePrivateKey(certKey, keyFile); err != nil {
		log.Fatalf("unable to write certificate private key: %s", err)
	}

	certPath := outputFile + ".crt"
	if _, err := os.Stat(certPath); err == nil {
		log.Fatalf("a certificate already exist: %q", certPath)
	}

	certFile, err := os.Create(certPath)
	if err != nil {
		log.Fatalln(err)
	}

	defer func() {
		if err := certFile.Close(); err != nil {
			log.Fatalf(`lv=err msg="Error closing certificate file" err=%s`, err)
		}
	}()

	if err := crypto.WriteCertificate(cert, certFile); err != nil {
		log.Fatalf("unable to write certificate: %s", err)
	}
}

func renew(args map[string]interface{}) {
	// Check expiration date, it it is within 45 days, renew it.
	// Otherwise, do not re-new it unless it is forced by user
}

func revoke(args map[string]interface{}) {

}

func keygen(args map[string]interface{}) {
	var bitSize int
	var err error
	keyType := args["--key-type"].(string)
	bs := args["--bit-size"]
	if bs != nil {
		bitSize, err = strconv.Atoi(bs.(string))
		if err != nil {
			log.Fatal(err)
		}
	}

	// Generates private key.
	key, err := crypto.Keygen(keyType, bitSize)
	if err != nil {
		log.Fatal(err)
	}

	outputDir := args["--output"].(string)

	// Private key
	prvPath := filepath.Join(outputDir, "private_key.pem")
	if _, err := os.Stat(prvPath); err == nil {
		log.Fatalf("a private key already exist: %q", prvPath)
	}

	prvFile, err := os.Create(prvPath)
	if err != nil {
		log.Fatalln(err)
	}

	defer func() {
		if err := prvFile.Close(); err != nil {
			log.Fatalf(`lv=err msg="Error closing private key file" err=%s`, err)
		}
	}()

	if err := crypto.WritePrivateKey(key, prvFile); err != nil {
		log.Fatalf("unable to store private key: %s", err)
	}

	// Public key
	pubPath := filepath.Join(outputDir, "public_key.pem")
	if _, err := os.Stat(pubPath); err == nil {
		log.Fatalf("a public key already exist: %q", pubPath)
	}

	pubFile, err := os.Create(pubPath)
	if err != nil {
		log.Fatalln(err)
	}

	defer func() {
		if err := pubFile.Close(); err != nil {
			log.Fatalf(`lv=err msg="Error closing public key file" err=%s`, err)
		}
	}()

	if err := crypto.WritePublicKey(key, pubFile); err != nil {
		log.Fatalf("unable to write public key: %s", err)
	}
}

func server(args map[string]interface{}) {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Letse TLS test server\n")
	})

	log.Printf(`
	Letse TLS test server.

	Add an entry to your /etc/hosts file so that you can test your certificate using
	its Common Name. Ex:

	127.0.0.1  v.hooklift.io
	`)

	log.Printf("Running TLS server on port 8080...\n")
	log.Fatal(http.ListenAndServeTLS(":8080", args["--cert"].(string), args["--cert-key"].(string), nil))
}
