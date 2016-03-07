# Simple Letsencrypt CLI - DNS challenges only (Work in Progress)

## Features
* Requests new ECDSA or RSA certificates for specific domains
* Renews certificates
* Revokes certificates
* Only DNS challenges supported
* Extendable to support multiple DNS providers, currently only Route53 is supported

## Usage
For Route53 make sure the following environment variables are set with
valid values before you run this CLI.

* AWS_ACCESS_KEY_ID
* AWS_SECRET_ACCESS_KEY
* AWS_REGION

```
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
```
