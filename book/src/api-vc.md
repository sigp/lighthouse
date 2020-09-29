# Validator Client API

Lighthouse implements a custom HTTP/JSON API for the validator client. A full
list of endpoints can be found in [Endpoints](./api-vc-endpoints.md).

All requests to the HTTP server must supply an
[`Authorization`](./api-vc-auth-header.md) header. All responses contain a
[`Signature`](./api-vc-sig-header.md) header for optional verification.

## Starting the server

A Lighthouse validator client can be configured to expose a HTTP server by supplying the `--http` flag. The default listen address is `127.0.0.1:5062`.

The following CLI flags control the HTTP server:

- `--http`: enable the HTTP server (required even if the following flags are
	provided).
- `--http-port`: specify the listen port of the server.
- `--http-address`: specify the listen address of the server.
- `--http-allow-origin`: specify the value of the `Access-Control-Allow-Origin`
		header. The default is to not supply a header.

### CLI Example

Start the validator client with the HTTP server listening on [http://localhost:5062](http://localhost:5062):

```bash
lighthouse vc --http
```
