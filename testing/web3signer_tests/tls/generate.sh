#!/bin/bash
openssl req -x509 -sha256 -nodes -days 36500 -newkey rsa:4096 -keyout web3signer/key.key -out web3signer/cert.pem -config web3signer/config &&
openssl pkcs12 -export -aes256 -out web3signer/key.p12 -inkey web3signer/key.key -in web3signer/cert.pem -password pass:$(cat web3signer/password.txt) &&
cp web3signer/cert.pem lighthouse/web3signer.pem &&
openssl req -x509 -sha256 -nodes -days 36500 -newkey rsa:4096 -keyout lighthouse/key.key -out lighthouse/cert.pem -config lighthouse/config &&
openssl pkcs12 -export -aes256 -out lighthouse/key.p12 -inkey lighthouse/key.key -in lighthouse/cert.pem -password pass:$(cat lighthouse/password.txt) &&
openssl x509 -noout -fingerprint -sha256 -inform pem -in lighthouse/cert.pem | cut -b 20-| sed "s/^/lighthouse /" > web3signer/known_clients.txt
