# Interop Cheat-sheet

This document contains a list of tips and tricks that may be useful during
interop testing.

- When starting a beacon node:
	- [Specify a boot node by multiaddr](#boot-node-multiaddr)
	- [Specify a boot node by ENR](#boot-node-enr)
	- [Avoid port clashes when starting multiple nodes](#port-bump)
	- [Specify a custom slot time](#slot-time)
- Using the beacon node HTTP API:
	- [Curl a node's ENR](#http-enr)
	- [Curl a node's connected peers](#http-peer-ids)
	- [Curl a node's local peer id](#http-peer-id)
	- [Curl a node's listening multiaddrs](#http-listen-addresses)
	- [Curl a node's beacon chain head](#http-head)
	- [Curl a node's finalized checkpoint](#http-finalized)

## Category: CLI

The `--help` command provides detail on the CLI interface. Here are some
interop-specific CLI commands.

<a name="boot-node-multiaddr"></a>
### Specify a boot node by multiaddr

You can specify a static list of multiaddrs when booting Lighthouse using
the `--libp2p-addresses` command.

#### Example:

Runs an 8 validator quick-start chain, peering with `/ip4/192.168.0.1/tcp/9000` on boot.

```
$ ./beacon_node --libp2p-addresses /ip4/192.168.0.1/tcp/9000 testnet -f quick 8 1567222226
```

<a name="boot-node-enr"></a>
### Specify a boot node by ENR

You can specify a static list of Discv5 addresses when booting Lighthouse using
the `--boot-nodes` command.

#### Example:

Runs an 8 validator quick-start chain, peering with `-IW4QB2...` on boot.

```
$ ./beacon_node --boot-nodes -IW4QB2Hi8TPuEzQ41Cdf1r2AUU1FFVFDBJdJyOkWk2qXpZfFZQy2YnJIyoT_5fnbtrXUouoskmydZl4pIg90clIkYUDgmlwhH8AAAGDdGNwgiMog3VkcIIjKIlzZWNwMjU2azGhAjg0-DsTkQynhJCRnLLttBK1RS78lmUkLa-wgzAi-Ob5 testnet -f quick 8 1567222226
```

<a name="port-bump"></a>
### Avoid port clashes when starting nodes

Starting a second Lighthouse node on the same machine will fail due to TCP/UDP
port collisions. Use the `-b` (`--port-bump`) flag to increase all listening
ports by some `n`.

#### Example:

Increase all ports by `10` (using multiples of `10` is recommended).

```
$ ./beacon_node -b 10 testnet -f quick 8 1567222226
```

<a name="slot-time"></a>
### Start a testnet with a custom slot time

Lighthouse can run at quite low slot times when there are few validators (e.g.,
`500 ms` slot times should be fine for 8 validators).

#### Example

The `-t` (`--slot-time`) flag specifies the milliseconds per slot.

```
$ ./beacon_node -b 10 testnet -t 500 -f quick 8 1567222226
```

> Note: `bootstrap` loads the slot time via HTTP and therefore conflicts with
> this flag.

## Category: HTTP API

Examples assume there is a Lighthouse node exposing a HTTP API on
`localhost:5052`. Responses are JSON.

<a name="http-enr"></a>
### Get the node's ENR

```
$ curl localhost:5052/network/enr

"-IW4QFyf1VlY5pZs0xZuvKMRZ9_cdl9WMCDAAJXZiZiuGcfRYoU40VPrYDLQj5prneJIz3zcbTjHp9BbThc-yiymJO8HgmlwhH8AAAGDdGNwgiMog3VkcIIjKIlzZWNwMjU2azGhAjg0-DsTkQynhJCRnLLttBK1RS78lmUkLa-wgzAi-Ob5"%
```

<a name="http-peer-ids"></a>
### Get a list of connected peer ids

```
$ curl localhost:5052/network/peers

["QmeMFRTWfo3KbVG7dEBXGhyRMa29yfmnJBXW84rKuGEhuL"]%
```

<a name="http-peer-id"></a>
### Get the node's peer id

```
curl localhost:5052/network/peer_id

"QmRD1qs2AqNNRdBcGHUGpUGkpih5cmdL32mhh22Sy79xsJ"%
```

<a name="http-listen-addresses"></a>
### Get the list of listening libp2p addresses

Lists all the libp2p multiaddrs that the node is listening on.

```
curl localhost:5052/network/listen_addresses

["/ip4/127.0.0.1/tcp/9000","/ip4/192.168.1.121/tcp/9000","/ip4/172.17.0.1/tcp/9000","/ip4/172.42.0.1/tcp/9000","/ip6/::1/tcp/9000","/ip6/fdd3:c293:1bc::203/tcp/9000","/ip6/fdd3:c293:1bc:0:9aa9:b2ea:c610:44db/tcp/9000"]%
```

<a name="http-head"></a>
### Get the node's beacon chain head

```
curl localhost:5052/beacon/head

{"slot":0,"block_root":"0x827bf71805540aa13f6d8c7d18b41b287b2094a4d7a28cbb8deb061dbf5df4f5","state_root":"0x90a78d73294bc9c7519a64e1912161be0e823eb472012ff54204e15a4d717fa5"}%
```

<a name="http-finalized"></a>
### Get the node's finalized checkpoint

```
curl localhost:5052/beacon/latest_finalized_checkpoint

{"epoch":0,"root":"0x0000000000000000000000000000000000000000000000000000000000000000"}%
```
