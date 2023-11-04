# Frequently Asked Questions

## 1. Are there any requirements to run Siren?
Yes, the most current Siren version requires Lighthouse v4.3.0 or higher to function properly. These releases can be found on the [releases](https://github.com/sigp/lighthouse/releases) page of the Lighthouse repository.

## 2. Where can I find my API token?
The required Api token may be found in the default data directory of the validator client. For more information please refer to the lighthouse ui configuration [`api token section`](./api-vc-auth-header.md).

## 3. How do I fix the Node Network Errors?
If you receive a red notification with a BEACON or VALIDATOR NODE NETWORK ERROR you can refer to the lighthouse ui configuration and [`connecting to clients section`](./ui-configuration.md#connecting-to-the-clients).

## 4. How do I connect Siren to Lighthouse from a different computer on the same network?
The most effective approach to enable access for a local network computer to Lighthouse's HTTP API ports is by configuring the `--http-address` to match the local LAN IP of the system running the beacon node and validator client. For instance, if the said node operates at `192.168.0.200`, this IP can be specified using the `--http-address` parameter as `--http-address 192.168.0.200`.
Subsequently, by designating the host as `192.168.0.200`, you can seamlessly connect Siren to this specific beacon node and validator client pair from any computer situated within the same network.

## 5. How can I use Siren to monitor my validators remotely when I am not at home?

There are two primary methods to access your Beacon Node and Validator Client remotely: setting up a VPN or utilizing SSH-reverse tunneling.

Most contemporary home routers provide options for VPN access in various ways. A VPN permits a remote computer to establish a connection with internal computers within a home network. With a VPN configuration in place, connecting to the VPN enables you to treat your computer as if it is part of your local home network. The connection process involves following the setup steps for connecting via another machine on the same network on the Siren configuration page and [`connecting to clients section`](./ui-configuration.md#connecting-to-the-clients).

In the absence of a VPN, an alternative approach involves utilizing an SSH tunnel. To achieve this, you need remote SSH access to the computer hosting the Beacon Node and Validator Client pair (which necessitates a port forward in your router). In this context, while it is not obligatory to set a `--http-address` flag on the Beacon Node and Validator Client, you can configure an SSH tunnel to the local ports on the node and establish a connection through the tunnel. For instructions on setting up an SSH tunnel, refer to [`Connecting Siren via SSH tunnel`](./ui-faqs.md#6-how-do-i-connect-siren-to-lighthouse-via-a-ssh-tunnel) for detailed guidance.

## 6. How do I connect Siren to Lighthouse via a ssh tunnel?
If you would like to access Siren beyond the local network (i.e across the internet), we recommend using an SSH tunnel. This requires a tunnel for 3 ports: `80` (assuming the port is unchanged as per the [installation guide](./ui-installation.md#docker-recommended), `5052` (for beacon node) and `5062` (for validator client). You can use the command below to perform SSH tunneling:

```bash

ssh -N -L 80:127.0.0.1:80 -L 5052:127.0.0.1:5052 -L 5062:127.0.0.1:5062 username@local_ip

```


Where `username` is the username of the server and `local_ip` is the local IP address of the server. Note that with the `-N` option in an SSH session, you will not be able to execute commands in the CLI to avoid confusion with ordinary shell sessions. The connection will appear to be "hung" upon a successful connection, but that is normal. Once you have successfully connected to the server via SSH tunneling, you should be able to access Siren by entering `localhost` in a web browser.


You can also access Siren using the app downloaded in the [Siren release page](https://github.com/sigp/siren/releases). To access Siren beyond the local computer, you can use SSH tunneling for ports `5052` and `5062` using the command:


```bash

ssh -N -L 5052:127.0.0.1:5052 -L 5062:127.0.0.1:5062 username@local_ip

```

## 7. Does Siren support reverse proxy or DNS named addresses?
Yes, if you need to access your beacon or validator from an address such as `https://merp-server:9909/eth2-vc` you should follow the following steps for configuration:
1. Toggle `https` as your protocol
2. Add your address as `merp-server/eth2-vc`
3. Add your Beacon and Validator ports as `9909`

If you have configured it correctly you should see a green checkmark indicating Siren is now connected to your Validator Client and Beacon Node.

If you have separate address setups for your Validator Client and Beacon Node respectively you should access the `Advance Settings` on the configuration and repeat the steps above for each address.


## 8. How do I change my Beacon or Validator address after logging in?
Once you have successfully arrived to the main dashboard, use the sidebar to access the settings view. In the top right hand corner there is a `Configuration` action button that will redirect you back to the configuration screen where you can make appropriate changes.

## 9. Why doesn't my validator balance graph show any data?
If your graph is not showing data, it usually means your validator node is still caching data. The application must wait at least 3 epochs before it can render any graphical visualizations. This could take up to 20min.
