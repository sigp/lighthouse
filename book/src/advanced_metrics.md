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
