# Validator Client API: Authorization Header

## Overview

The validator client HTTP server requires that all requests have the following
HTTP header:

- Name: `Authorization`
- Value: `Basic <api-token>`

Where `<api-token>` is a string that can be obtained from the validator client
host. Here is an example `<api-token>` value:

```
api-token-0x03400ca133ef69cacc70b24fa7a17bdd62bd56d0c572c7ea825a461497cd1d9e14
```

## Obtaining the API token

The API token can be obtained via two methods:

### Method 1: Reading from a file

The API token is stored as a file in the `validators` directory. For most users
this is `~/.lighthouse/validators/api-secret-access-token.txt`. Here's an
example using the `cat` command to print the token to the terminal, but any
text editor will suffice:

```
$ cat api-token.txt
api-token-0x03400ca133ef69cacc70b24fa7a17bdd62bd56d0c572c7ea825a461497cd1d9e14
```

### Method 2: Reading from logs

When starting the validator client, the validator client will output a log
message containing an `api-token` field:

```
Sep 28 19:17:52.615 INFO HTTP API started                        api_token: api-token-0x03400ca133ef69cacc70b24fa7a17bdd62bd56d0c572c7ea825a461497cd1d9e14, listen_address: 127.0.0.1:5062
```

## Example

Here is an example `curl` command using the API token in the `Authorization` header:

```bash
curl localhost:5062/lighthouse/version -H "Authorization: Basic api-token-0x03400ca133ef69cacc70b24fa7a17bdd62bd56d0c572c7ea825a461497cd1d9e14"
```

The server should respond with its version:

```json
{"data":{"version":"Lighthouse/v0.2.11-498776e61/x86_64-linux"}}
```
