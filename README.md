A wiki.

### Generating a cert.pem and key.pem
 1. Generate a new unencrypted rsa private key in PEM format:
  * ```openssl genrsa -out privkey.pem 1024```
 1. Create a certificate signing request (CSR) using your rsa private key:
  * ```openssl req -new -key privkey.pem -out certreq.csr```
 1. Self-sign your CSR with your own private key:
  * ```openssl x509 -req -days 3650 -in certreq.csr -signkey privkey.pem -out newcert.pem```
