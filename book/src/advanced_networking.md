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
often be requesting a large number of blocks from your node. This means you
node must perform a lot of work reading and responding to these peers. If you
node is over-loaded with peers and cannot respond in time, other Lighthouse
peers will consider you non-performant and disfavour you from their peer
stores. You node will also have to handle and manage the gossip and extra
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

Lighthouse, by default, used port 9000 for both TCP and UDP. Lighthouse will
still function if it is behind a NAT without any port mappings. Although
Lighthouse still functions, we recommend that some mechanism is used to ensure
that your Lighthouse node is publicly accessible. This will typically improve
your peer count, allow the scoring system to find the best/most favourable
peers for your node and overall improve the eth2 network.

Lighthouse currently supports UPnP. If UPnP is enabled on your router,
Lighthouse will automatically establish the port mappings for you (the beacon
node will inform you of established routes in this case). If UPnP is not
enabled, we recommend you manually set up port mappings to both of Lighthouse's
TCP and UDP ports (9000 by default).

### ENR Configuration

Lighthouse has a number of CLI parameters for constructing and modifying the
local Ethereum Node Record (ENR). Examples are `--enr-address`,
`--enr-udp-port`, `--enr-tcp-port` and `--disable-enr-auto-update`. These
settings allow you construct your initial ENR. Their primary intention is for
setting up boot-like nodes and having a contactable ENR on boot. On normal
operation of a Lighthouse node, none of these flags need to be set. Setting
these flags incorrectly can lead to your node being incorrectly added to the
global DHT which will degrades the discovery process for all Eth2 peers.

The ENR of a Lighthouse node is initially set to be non-contactable. The
in-built discovery mechanism can determine if you node is publicly accessible,
and if it is, it will update your ENR to the correct public IP and port address
(meaning you do not need to set it manually). Lighthouse persists its ENR, so
on reboot it will re-load the settings it had discovered previously.

Modifying the ENR settings can degrade the discovery of your node making it
harder for peers to find you or potentially making it harder for other peers to
find each other. We recommend not touching these settings unless for a more
advanced use case.
