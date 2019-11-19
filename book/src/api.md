# APIs

The Lighthouse `beacon_node` provides two APIs for local consumption:

- A [RESTful JSON HTTP API](http.html) which provides beacon chain, node and network
	information.
- A read-only [WebSocket API](websockets.html) providing beacon chain events, as they occur.


## Security

These endpoints are not designed to be exposed to the public Internet or
untrusted users. They may pose a considerable DoS attack vector when used improperly.
