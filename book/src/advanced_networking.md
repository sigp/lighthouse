# Advanced Networking

Lighthouse's networking stack has a number of configurable parameters that can
be adjusted to handle a variety of network situations. This section outlines
some of these configuration parameters and their consequences at the networking
level and their general intended use.


### Target Peers

The beacon node has a `--target-peers` CLI parameter. This allows you to
instruct the beacon node how many peers it should try to find and maintain.
Lighthouse allows an additional 10% of this value for nodes to connect to us.
Every 30 seconds, the excess peers are pruned. Lighthouse removes the
worst-performing peers and maintains the best performing peers.

It may be counter-intuitive, but having a very large peer count will likely
have a degraded performance for a beacon node in normal operation and during
sync.

Having a large peer count means that your node must act as an honest RPC server
to all your connected peers. If there are many that are syncing, they will
often be requesting a large number of blocks from your node. This means your
node must perform a lot of work reading and responding to these peers. If your
node is overloaded with peers and cannot respond in time, other Lighthouse
peers will consider you non-performant and disfavour you from their peer
stores. Your node will also have to handle and manage the gossip and extra
bandwidth that comes from having these extra peers. Having a non-responsive
node (due to overloading of connected peers), degrades the network as a whole.

It is often the belief that a higher peer counts will improve sync times.
Beyond a handful of peers, this is not true. On all current tested networks,
the bottleneck for syncing is not the network bandwidth of downloading blocks,
rather it is the CPU load of processing the blocks themselves. Most of the
time, the network is idle, waiting for blocks to be processed. Having a very
large peer count will not speed up sync.

For these reasons, we recommend users do not modify the `--target-peers` count
drastically and use the (recommended) default.

### NAT Traversal (Port Forwarding)

Lighthouse, by default, uses port 9000 for both TCP and UDP. Lighthouse will
still function if it is behind a NAT without any port mappings. Although
Lighthouse still functions, we recommend that some mechanism is used to ensure
that your Lighthouse node is publicly accessible. This will typically improve
your peer count, allow the scoring system to find the best/most favourable
peers for your node and overall improve the Ethereum consensus network.

Lighthouse currently supports UPnP. If UPnP is enabled on your router,
Lighthouse will automatically establish the port mappings for you (the beacon
node will inform you of established routes in this case). If UPnP is not
enabled, we recommend you to manually set up port mappings to both of Lighthouse's
TCP and UDP ports (9000 by default).

> Note: Lighthouse needs to advertise its publicly accessible ports in
> order to inform its peers that it is contactable and how to connect to it.
> Lighthouse has an automated way of doing this for the UDP port. This means
> Lighthouse can detect its external UDP port. There is no such mechanism for the
> TCP port. As such, we assume that the external UDP and external TCP port is the
> same (i.e external 5050 UDP/TCP mapping to internal 9000 is fine). If you are setting up differing external UDP and TCP ports, you should
> explicitly specify them using the `--enr-tcp-port` and `--enr-udp-port` as
> explained in the following section.

### How to Open Ports

The steps to do port forwarding depends on the router, but the general steps are given below:
1. Determine the default gateway IP:
- On Linux: open a terminal and run `ip route | grep default`, the result should look something similar to `default via 192.168.50.1 dev wlp2s0 proto dhcp metric 600`. The `192.168.50.1` is your router management default gateway IP. 
- On MacOS: open a terminal and run `netstat -nr|grep default` and it should return the default gateway IP.
- On Windows: open a command prompt and run `ipconfig` and look for the `Default Gateway` which will show you the gateway IP.

  The default gateway IP usually looks like 192.168.X.X. Once you obtain the IP, enter it to a web browser and it will lead you to the router management page.

2. Login to the router management page. The login credentials are usually available in the manual or the router, or it can be found on a sticker underneath the router. You can also try the login credentials for some common router brands listed [here](https://www.noip.com/support/knowledgebase/general-port-forwarding-guide/).

3. Navigate to the port forward settings in your router. The exact step depends on the router, but typically it will fall under the "Advanced" section, under the name "port forwarding" or "virtual server". 

4. Configure a port forwarding rule as below:
- Protocol: select `TCP/UDP` or `BOTH`
- External port: `9000`
- Internal port: `9000`
- IP address: Usually there is a dropdown list for you to select the device. Choose the device that is running Lighthouse

5. To check that you have successfully open the ports, go to [yougetsignal](https://www.yougetsignal.com/tools/open-ports/) and enter `9000` in the `port number`. If it shows "open", then you have successfully set up port forwarding. If it shows "closed", double check your settings, and also check that you have allowed firewall rules on port 9000. 


### ENR Configuration

Lighthouse has a number of CLI parameters for constructing and modifying the
local Ethereum Node Record (ENR). Examples are `--enr-address`,
`--enr-udp-port`, `--enr-tcp-port` and `--disable-enr-auto-update`. These
settings allow you to construct your initial ENR. Their primary intention is for
setting up boot-like nodes and having a contactable ENR on boot. On normal
operation of a Lighthouse node, none of these flags need to be set. Setting
these flags incorrectly can lead to your node being incorrectly added to the
global DHT which will degrade the discovery process for all Ethereum consensus peers.

The ENR of a Lighthouse node is initially set to be non-contactable. The
in-built discovery mechanism can determine if your node is publicly accessible,
and if it is, it will update your ENR to the correct public IP and port address
(meaning you do not need to set it manually). Lighthouse persists its ENR, so
on reboot it will re-load the settings it had discovered previously.

Modifying the ENR settings can degrade the discovery of your node, making it
harder for peers to find you or potentially making it harder for other peers to
find each other. We recommend not touching these settings unless for a more
advanced use case.


### IPv6 support

As noted in the previous sections, two fundamental parts to ensure good
connectivity are: The parameters that configure the sockets over which
Lighthouse listens for connections, and the parameters used to tell other peers
how to connect to your node. This distinction is relevant and applies to most
nodes that do not run directly on a public network.

#### Configuring Lighthouse to listen over IPv4/IPv6/Dual stack

To listen over only IPv6 use the same parameters as done when listening over
IPv4 only:

- `--listen-address :: --port 9909` will listen over IPv6 using port `9909` for
TCP and UDP.
- `--listen-address :: --port 9909 --discovery-port 9999` will listen over
  IPv6 using port `9909` for TCP and port `9999` for UDP.

To listen over both IPv4 and IPv6:
- Set two listening addresses using the `--listen-address` flag twice ensuring
  the two addresses are one IPv4, and the other IPv6. When doing so, the
  `--port` and `--discovery-port` flags will apply exclusively to IPv4. Note
  that this behaviour differs from the Ipv6 only case described above.
- If necessary, set the `--port6` flag to configure the port used for TCP and
  UDP over IPv6. This flag has no effect when listening over IPv6 only.
- If necessary, set the `--discovery-port6` flag to configure the IPv6  UDP
  port. This will default to the value given to `--port6` if not set. This flag
  has no effect when listening over IPv6 only.

##### Configuration Examples

- `--listen-address :: --listen-address 0.0.0.0 --port 9909` will listen
  over IPv4 using port `9909` for TCP and UDP. It will also listen over IPv6 but
  using the default value for `--port6` for UDP and TCP (`9090`).
- `--listen-address :: --listen-address --port 9909 --discovery-port6 9999`
  will have the same configuration as before except for the IPv6 UDP socket,
  which will use port `9999`.

#### Configuring Lighthouse to advertise IPv6 reachable addresses
Lighthouse supports IPv6 to connect to other nodes both over IPv6 exclusively,
and dual stack using one socket for IPv4 and another socket for IPv6. In both
scenarios, the previous sections still apply. In summary:

> Beacon nodes must advertise their publicly reachable socket address

In order to do so, lighthouse provides the following CLI options/parameters.

- `--enr-udp-port` Use this to advertise the port that is publicly reachable
  over UDP with a publicly reachable IPv4 address. This might differ from the
  IPv4 port used to listen.
- `--enr-udp6-port` Use this to advertise the port that is publicly reachable
  over UDP with a publicly reachable IPv6 address. This might differ from the
  IPv6 port used to listen.
- `--enr-tcp-port` Use this to advertise the port that is publicly reachable
  over TCP with a publicly reachable IPv4 address. This might differ from the
  IPv4 port used to listen.
- `--enr-tcp6-port` Use this to advertise the port that is publicly reachable
  over TCP with a publicly reachable IPv6 address. This might differ from the
  IPv6 port used to listen.
- `--enr-addresses` Use this to advertise publicly reachable addresses. Takes at
  most two values, one for IPv4 and one for IPv6. Note that a beacon node that
  advertises some address, must be
  reachable both over UDP and TCP.

In the general case, a user will not require to set these explicitly. Update
these options only if you can guarantee your node is reachable with these
values.

#### Known caveats

IPv6 link local addresses are likely to have poor connectivity if used in
topologies with more than one interface. Use global addresses for the general
case.
