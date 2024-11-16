#!/bin/bash

# The lighthouse/key_legacy.p12 file is generated specifically for macOS because the default `openssl pkcs12` encoding
# algorithm in OpenSSL v3 is not compatible with the PKCS algorithm used by the Apple Security Framework. The client
# side (using the reqwest crate) relies on the Apple Security Framework to parse PKCS files.
# We don't need to generate web3signer/key_legacy.p12 because the compatibility issue doesn't occur on the web3signer
# side. It seems that web3signer (Java) uses its own implementation to parse PKCS files.
# See https://github.com/sigp/lighthouse/issues/6442#issuecomment-2469252651

# We specify `-days 825` when generating the certificate files because Apple requires TLS server certificates to have a
# validity period of 825 days or fewer.
# See https://github.com/sigp/lighthouse/issues/6442#issuecomment-2474979183

openssl req -x509 -sha256 -nodes -days 825 -newkey rsa:4096 -keyout web3signer/key.key -out web3signer/cert.pem -config web3signer/config &&
openssl pkcs12 -export -out web3signer/key.p12 -inkey web3signer/key.key -in web3signer/cert.pem -password pass:$(cat web3signer/password.txt) &&
cp web3signer/cert.pem lighthouse/web3signer.pem &&
openssl req -x509 -sha256 -nodes -days 825 -newkey rsa:4096 -keyout lighthouse/key.key -out lighthouse/cert.pem -config lighthouse/config &&
openssl pkcs12 -export -out lighthouse/key.p12 -inkey lighthouse/key.key -in lighthouse/cert.pem -password pass:$(cat lighthouse/password.txt) &&
openssl pkcs12 -export -legacy -out lighthouse/key_legacy.p12 -inkey lighthouse/key.key -in lighthouse/cert.pem -password pass:$(cat lighthouse/password.txt) &&
openssl x509 -noout -fingerprint -sha256 -inform pem -in lighthouse/cert.pem | cut -b 20-| sed "s/^/lighthouse /" > web3signer/known_clients.txt
