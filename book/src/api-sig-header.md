# Validator Client API: Authorization Header

## Overview

The validator client HTTP server adds the following header to all responses:

- Name: `Signature`
- Value: `<signature>`

Where `<signature>` is an secp256k1 signature across the body of the response.
Here is an example `<signature>` value:

```
0xa82c79be4855ed18e2d9fb1f3c34d203061d5e515d568e40c94699db95558824002a7195b928a5e5694fa4fb0c71c0e98ec4ee682fd3b81a14f74e905b9e4ea7
```

## Verifying the signature

TODO

## Example

Here is an example `curl` command using the API token in the `Authorization` header:

```bash
curl -v localhost:5062/lighthouse/version -H "Authorization: Basic api-token-0x03400ca133ef69cacc70b24fa7a17bdd62bd56d0c572c7ea825a461497cd1d9e14"
```

The server should respond with its version and a `Signature` header:

```
curl -v localhost:5062/lighthouse/version -H "Authorization: Basic
api-token-0x03400ca133ef69cacc70b24fa7a17bdd62bd56d0c572c7ea825a461497cd1d9e14"
*   Trying ::1:5062...
*   * connect to ::1 port 5062 failed: Connection refused
*   *   Trying 127.0.0.1:5062...
*   * Connected to localhost (127.0.0.1) port 5062 (#0)
*   > GET /lighthouse/version HTTP/1.1
*   > Host: localhost:5062
*   > User-Agent: curl/7.72.0
*   > Accept: */*
*   > Authorization: Basic
api-token-0x03400ca133ef69cacc70b24fa7a17bdd62bd56d0c572c7ea825a461497cd1d9e14
>
>* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< content-type: application/json
< signature:
0xa82c79be4855ed18e2d9fb1f3c34d203061d5e515d568e40c94699db95558824002a7195b928a5e5694fa4fb0c71c0e98ec4ee682fd3b81a14f74e905b9e4ea7
< server: Lighthouse/v0.2.11-498776e61+/x86_64-linux
< access-control-allow-origin:
< content-length: 65
< date: Mon, 28 Sep 2020 09:26:07 GMT
<
* Connection #0 to host localhost left intact
* {"data":{"version":"Lighthouse/v0.2.11-498776e61+/x86_64-linux"}}
```
