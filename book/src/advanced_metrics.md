# Prometheus Metrics

Lighthouse provides an extensive suite of metrics and monitoring in the
[Prometheus](https://prometheus.io/docs/introduction/overview/) export format
via a HTTP server built into Lighthouse.

These metrics are generally consumed by a Prometheus server and displayed via a
Grafana dashboard. These components are available in a docker-compose format at
[sigp/lighthouse-metrics](https://github.com/sigp/lighthouse-metrics).

## Beacon Node Metrics

By default, these metrics are disabled but can be enabled with the `--metrics`
flag. Use the `--metrics-address`, `--metrics-port` and
`--metrics-allow-origin` flags to customize the metrics server.

### Example

Start a beacon node with the metrics server enabled:

```bash
lighthouse bn --metrics
```

Check to ensure that the metrics are available on the default port:

```bash
curl localhost:5054/metrics
```

## Validator Client Metrics


By default, these metrics are disabled but can be enabled with the `--metrics`
flag. Use the `--metrics-address`, `--metrics-port` and
`--metrics-allow-origin` flags to customize the metrics server.

### Example

Start a validator client with the metrics server enabled:

```bash
lighthouse vc --metrics
```

Check to ensure that the metrics are available on the default port:

```bash
curl localhost:5064/metrics
```

## Remote Monitoring

Lighthouse has the ability to send a subset of metrics to a remote server for collection. Presently
the main server offering remote monitoring is beaconcha.in. Instructions for setting this up
can be found in beaconcha.in's docs:

- <https://kb.beaconcha.in/beaconcha.in-explorer/mobile-app-less-than-greater-than-beacon-node>

The Lighthouse flag for setting the monitoring URL is `--monitoring-endpoint`.

When sending metrics to a remote server you should be conscious of security:

- Only use a monitoring service that you trust: you are sending detailed information about
  your validators and beacon node to this service which could be used to track you.
- Always use an HTTPS URL to prevent the traffic being intercepted in transit.

The specification for the monitoring endpoint can be found here:

- <https://github.com/gobitfly/eth2-client-metrics>

_Note: the similarly named [Validator Monitor](./validator-monitoring.md) feature is entirely
independent of remote metric monitoring_.

### Update Period

You can adjust the frequency at which Lighthouse sends metrics to the remote server using the
`--monitoring-endpoint-period` flag. It takes an integer value in seconds, defaulting to 60
seconds.

```
lighthouse bn --monitoring-endpoint-period 60 --monitoring-endpoint "https://url"
```

Increasing the monitoring period between can be useful if you are running into rate limits when
posting large amounts of data for multiple nodes.
