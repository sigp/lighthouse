#!/bin/bash
openssl req -x509 -sha256 -nodes -days 36500 -newkey rsa:4096 -keyout key.key -out cert.pem -config config &&
openssl pkcs12 -export -out key.p12 -inkey key.key -in cert.pem -password pass:$(cat password.txt)

