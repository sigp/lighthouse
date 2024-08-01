# Frequently Asked Questions

## 1. Are there any requirements to run Siren?

Yes, the most current Siren version requires Lighthouse v4.3.0 or higher to function properly. These releases can be found on the [releases](https://github.com/sigp/lighthouse/releases) page of the Lighthouse repository.

## 2. Where can I find my API token?

The required Api token may be found in the default data directory of the validator client. For more information please refer to the lighthouse ui configuration [`api token section`](./api-vc-auth-header.md).

## 3. How do I fix the Node Network Errors?

If you receive a red notification with a BEACON or VALIDATOR NODE NETWORK ERROR you can refer to the lighthouse ui configuration and [`connecting to clients section`](./ui-configuration.md#connecting-to-the-clients).

## 4. How do I connect Siren to Lighthouse from a different computer on the same network?

Siren is a webapp, you can access it like any other website. We don't recommend exposing it to the internet; if you require remote access a VPN or (authenticated) reverse proxy is highly recommended.

## 5. How can I use Siren to monitor my validators remotely when I am not at home?

Most contemporary home routers provide options for VPN access in various ways. A VPN permits a remote computer to establish a connection with internal computers within a home network. With a VPN configuration in place, connecting to the VPN enables you to treat your computer as if it is part of your local home network. The connection process involves following the setup steps for connecting via another machine on the same network on the Siren configuration page and [`connecting to clients section`](./ui-configuration.md#connecting-to-the-clients).

## 6. Does Siren support reverse proxy or DNS named addresses?

Yes, if you need to access your beacon or validator from an address such as `https://merp-server:9909/eth2-vc` you should configure Siren as follows:  
`VALIDATOR_URL=https://merp-server:9909/eth2-vc`

## 7. Why doesn't my validator balance graph show any data?

If your graph is not showing data, it usually means your validator node is still caching data. The application must wait at least 3 epochs before it can render any graphical visualizations. This could take up to 20min.
