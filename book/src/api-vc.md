# Validator Client API

Lighthouse implements a HTTP/JSON API for the validator client. Since there is
no Eth2 standard validator client API, Lighthouse has defined its own.

A full list of endpoints can be found in [Endpoints](./api-vc-endpoints.md).

> Note: All requests to the HTTP server must supply an
> [`Authorization`](./api-vc-auth-header.md) header. All responses contain a
> [`Signature`](./api-vc-sig-header.md) header for optional verification.

## Starting the server

A Lighthouse validator client can be configured to expose a HTTP server by supplying the `--http` flag. The default listen address is `127.0.0.1:5062`.

The following CLI flags control the HTTP server:

- `--http`: enable the HTTP server (required even if the following flags are
	provided).
- `--http-port`: specify the listen port of the server.
- `--http-allow-origin`: specify the value of the `Access-Control-Allow-Origin`
		header. The default is to not supply a header.

## Security

The validator client HTTP is **not encrypted** (i.e., it is **not HTTPS**). For
this reason, it will only listen on `127.0.0.1`.

It is unsafe to expose the validator client to the public Internet without
additional transport layer security (e.g., HTTPS via nginx, SSH tunnels, etc.).

### CLI Example

Start the validator client with the HTTP server listening on [http://localhost:5062](http://localhost:5062):

```bash
lighthouse vc --http
```
