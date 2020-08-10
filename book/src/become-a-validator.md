# Become an Ethereum 2.0 Validator

There are two public testnets currently available. [Medalla](https://github.com/goerli/medalla/tree/master/medalla) and [Altona](https://github.com/goerli/medalla/tree/master/altona). Lighthouse supports both out of the box and joining these multi-client testnets is easy if you're familiar with the terminal.

Lighthouse runs on Linux, MacOS and Windows and has a Docker work-flow to make
things as simple as possible.

## 0. Acquire Goerli ETH
Before you install Lighthouse, you'll need [Metamask](https://metamask.io/) and 32 gETH
(Goerli ETH). We recommend the [mudit.blog
faucet](https://faucet.goerli.mudit.blog/) for those familiar with Goerli, or
[goerli.net](https://goerli.net/) for an overview of the testnet.

> If this is your first time using Metamask and/or interacting with an Ethereum test network, we recommend going through the beginning of [this guide](https://hack.aragon.org/docs/guides-use-metamask) first (up to the *Signing your first transaction with MetaMask* section).

## 1. Install and start Lighthouse

There are two, different ways to install and start a Lighthouse validator:

1. [Using `docker-compose`](./become-a-validator-docker.md): this is the easiest method.

2. [Building from source](./become-a-validator-source.md): this is a little more involved, however it
   gives a more hands-on experience.

Once you've completed **either one** of these steps, you can move onto the next step.

> Take note when running Lighthouse. Use the --testnet parameter to specify the testnet you whish to participate in. Medalla is currently the default, so make sure to use --testnet altona to join the Altona testnet.


## 2. Submit your deposit to Goerli

<div class="form-signin" id="uploadDiv">
	<p>Upload the <code>eth1_deposit_data.rlp</code> file from your validator
	directory (created in the previous step) to submit your 32 Goerli-ETH
	deposit using Metamask.</p>
	<p>Note that the method you used in step 1 will determine where this file is
	located.</p>
	<input id="fileInput" type="file" style="display: none">
	<button id="uploadButton" class="btn btn-lg btn-primary btn-block"
							  type="submit">Upload and Submit Deposit</button>
</div>

<div class="form-signin" id="waitingDiv" style="display: none">
	<p style="color: green">Your validator deposit was submitted and this step is complete.</p>
	<p>See the transaction on <a id="txLink" target="_blank"
											 href="https://etherscan.io">Etherscan</a>
	or <a href="">reload</a> to perform another deposit.</p>
</div>

<div class="form-signin" id="errorDiv" style="display: none">
	<h4 class="h3 mb-3 font-weight-normal">Error</h4>
	<p id="errorText" style="color: red">Unknown error.</p>
	<p style="color: red">Please refresh to reupload.</p>
</div>

> This deposit is made using gETH (Goerli ETH) which has no real value. Please don't ever
> send _real_ ETH to our deposit contract!

## 3. Leave Lighthouse running

Leave your beacon node and validator client running and you'll see logs as the
beacon node stays synced with the network while the validator client produces
blocks and attestations.

It will take 4-8+ hours for the beacon chain to process and activate your
validator, however you'll know you're active when the validator client starts
successfully publishing attestations each slot:

```
Dec 03 08:49:40.053 INFO Successfully published attestation      slot: 98, committee_index: 0, head_block: 0xa208…7fd5,
```

Although you'll produce an attestation each slot, it's less common to produce a
block. Watch for the block production logs too:

```
Dec 03 08:49:36.225 INFO Successfully published block            slot: 98, attestations: 2, deposits: 0, service: block
```

If you see any `ERRO` (error) logs, please reach out on
[Discord](https://discord.gg/cyAszAh) or [create an
issue](https://github.com/sigp/lighthouse/issues/new).

Don't forget to checkout the open-source block explorer for the Lighthouse
testnet at
[lighthouse-testnet3.beaconcha.in](https://lighthouse-testnet3.beaconcha.in/).

Happy staking!

## Optional: Resuming a node after an extended period of downtime

Barring test networks, when a node is offline for an extended period[^1], it
is necessary to obtain a state and block hash from another trusted node, in
order to catch up with the chain in a safe manner.

It's done via querying the trusted node's HTTP API.  `localhost` should be
substituted with the address (IP or DNS name) of a node that we rely on:

```
$ curl http://localhost:5052/beacon/weak_subjectivity_checkpoint | json_pp
{
   "state_root" : "0xa7e9875cdd78079a3a9ce2e517e5b852ccdf30505c77fe3fd745b512d75fc451",
   "block_root" : "0x4a46046175b459e68bc79da0d15d988d43681ec66a8e4bb05cc6d5d897eab56c"
}
$ curl -H "Accept: application/ssz" 'http://localhost:5052/beacon/block?bare=1&root=0x4a46046175b459e68bc79da0d15d988d43681ec66a8e4bb05cc6d5d897eab56c' >block.ssz
$ curl -H "Accept: application/ssz" 'http://localhost:5052/beacon/state?bare=1&root=0xa7e9875cdd78079a3a9ce2e517e5b852ccdf30505c77fe3fd745b512d75fc451' >state.ssz
```

Note the `bare` parameter in the URLs.  If not used, the output will be
malformed and lighthouse will complain at startup.

The files `block.ssz` and `state.ssz` should be copied onto a local machine
and their paths should be passed to Lighthouse at the command line:

```
$ lighthouse beacon --weakly-subjective-state=state.ssz --weakly-subjective-block=block.ssz
```

[^1]: See https://notes.ethereum.org/@adiasg/weak-subjectvity-eth2 for exact values


<script src="https://ajax.googleapis.com/ajax/libs/jquery/1.11.1/jquery.min.js"></script>
<script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js"></script>
<script charset="utf-8"
		src="https://cdn.ethers.io/scripts/ethers-v4.min.js"
		type="text/javascript">
</script>
<script src="js/deposit.js"></script>
