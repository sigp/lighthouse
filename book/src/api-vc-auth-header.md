# Validator Client API: Authorization Header

## Overview

The validator client HTTP server requires that all requests have the following
HTTP header:

- Name: `Authorization`
- Value: `Bearer <api-token>`

Where `<api-token>` is a string that can be obtained from the validator client
host. Here is an example `Authorization` header:

```text
Authorization: Bearer api-token-0x03eace4c98e8f77477bb99efb74f9af10d800bd3318f92c33b719a4644254d4123
```

## Obtaining the API token

The API token is stored as a file in the `validators` directory. For most users
this is `~/.lighthouse/{network}/validators/api-token.txt`. Here's an
example using the `cat` command to print the token to the terminal, but any
text editor will suffice:

```bash
cat api-token.txt
api-token-0x03eace4c98e8f77477bb99efb74f9af10d800bd3318f92c33b719a4644254d4123
```

When starting the validator client it will output a log message containing the path
to the file containing the api token.

```text
Sep 28 19:17:52.615 INFO HTTP API started                        api_token_file: "$HOME/holesky/validators/api-token.txt", listen_address: 127.0.0.1:5062
```

The _path_ to the API token may also be fetched from the HTTP API itself (this endpoint is the only
one accessible without the token):

```bash
curl http://localhost:5062/lighthouse/auth
```

Response:

```json
{
    "token_path": "/home/karlm/.lighthouse/holesky/validators/api-token.txt"
}
```

## Example

Here is an example `curl` command using the API token in the `Authorization` header:

```bash
curl localhost:5062/lighthouse/version -H "Authorization: Bearer api-token-0x03eace4c98e8f77477bb99efb74f9af10d800bd3318f92c33b719a4644254d4123"
```

The server should respond with its version:

```json
{"data":{"version":"Lighthouse/v0.2.11-fc0654fbe+/x86_64-linux"}}
```
