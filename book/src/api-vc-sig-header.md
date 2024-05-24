# Validator Client API: Signature Header

## Overview

The validator client HTTP server adds the following header to all responses:

- Name: `Signature`
- Value: a secp256k1 signature across the SHA256 of the response body.

Example `Signature` header:

```text
Signature: 0x304402205b114366444112580bf455d919401e9c869f5af067cd496016ab70d428b5a99d0220067aede1eb5819eecfd5dd7a2b57c5ac2b98f25a7be214b05684b04523aef873
```

## Verifying the Signature

Below is a browser-ready example of signature verification.

### HTML

```html
<script src="https://rawgit.com/emn178/js-sha256/master/src/sha256.js" type="text/javascript"></script>
<script src="https://rawgit.com/indutny/elliptic/master/dist/elliptic.min.js" type="text/javascript"></script>
```

### Javascript

```javascript
// Helper function to turn a hex-string into bytes.
function hexStringToByte(str) {
  if (!str) {
    return new Uint8Array();
  }

  var a = [];
  for (var i = 0, len = str.length; i < len; i+=2) {
    a.push(parseInt(str.substr(i,2),16));
  }

  return new Uint8Array(a);
}

// This example uses the secp256k1 curve from the "elliptic" library:
//
// https://github.com/indutny/elliptic
var ec = new elliptic.ec('secp256k1');

// The public key is contained in the API token:
//
// Authorization: Basic api-token-0x03eace4c98e8f77477bb99efb74f9af10d800bd3318f92c33b719a4644254d4123
var pk_bytes = hexStringToByte('03eace4c98e8f77477bb99efb74f9af10d800bd3318f92c33b719a4644254d4123');

// The signature is in the `Signature` header of the response:
//
// Signature: 0x304402205b114366444112580bf455d919401e9c869f5af067cd496016ab70d428b5a99d0220067aede1eb5819eecfd5dd7a2b57c5ac2b98f25a7be214b05684b04523aef873
var sig_bytes = hexStringToByte('304402205b114366444112580bf455d919401e9c869f5af067cd496016ab70d428b5a99d0220067aede1eb5819eecfd5dd7a2b57c5ac2b98f25a7be214b05684b04523aef873');

// The HTTP response body.
var response_body = "{\"data\":{\"version\":\"Lighthouse/v0.2.11-fc0654fbe+/x86_64-linux\"}}";

// The HTTP response body is hashed (SHA256) to determine the 32-byte message.
let hash = sha256.create();
hash.update(response_body);
let message = hash.array();

// The 32-byte message hash, the signature and the public key are verified.
if (ec.verify(message, sig_bytes, pk_bytes)) {
  console.log("The signature is valid")
} else {
  console.log("The signature is invalid")
}
```

*This example is also available as a [JSFiddle](https://jsfiddle.net/wnqd74Lz/).*

## Example

The previous Javascript example was written using the output from the following
`curl` command:

```bash
curl -v localhost:5062/lighthouse/version -H "Authorization: Basic api-token-0x03eace4c98e8f77477bb99efb74f9af10d800bd3318f92c33b719a4644254d4123"
```

```text
*   Trying ::1:5062...
* connect to ::1 port 5062 failed: Connection refused
*   Trying 127.0.0.1:5062...
* Connected to localhost (127.0.0.1) port 5062 (#0)
> GET /lighthouse/version HTTP/1.1
> Host: localhost:5062
> User-Agent: curl/7.72.0
> Accept: */*
> Authorization: Basic api-token-0x03eace4c98e8f77477bb99efb74f9af10d800bd3318f92c33b719a4644254d4123
>
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< content-type: application/json
< signature: 0x304402205b114366444112580bf455d919401e9c869f5af067cd496016ab70d428b5a99d0220067aede1eb5819eecfd5dd7a2b57c5ac2b98f25a7be214b05684b04523aef873
< server: Lighthouse/v0.2.11-fc0654fbe+/x86_64-linux
< access-control-allow-origin:
< content-length: 65
< date: Tue, 29 Sep 2020 04:23:46 GMT
<
* Connection #0 to host localhost left intact
{"data":{"version":"Lighthouse/v0.2.11-fc0654fbe+/x86_64-linux"}}
```
