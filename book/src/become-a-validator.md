# Become an Ethereum 2.0 Validator*

_* Testnet validator_

---
**The lighthouse testnet is currently down. We expect to bring it up again in
late-January or early-February. Thanks to all who participated in the testnet,
we look forward to having your input again in the future.**
---

Running Lighthouse validator is easy if you're familiar with the terminal. It
runs on Linux, MacOS and Windows and we have a Docker work-flow.

Before you start, you'll need [Metamask](https://metamask.io/) and 3.2 gETH
(Goerli ETH). We recommend the [mudit.blog
faucet](https://faucet.goerli.mudit.blog/) for those familiar with Goerli, or
[goerli.net](https://goerli.net/) for an overview of the testnet.

## 1. Install and start Lighthouse

There are two, different ways to install and start a Lighthouse validator:

- [Using `docker-compose`](./become-a-validator-docker.md): this is the easiest method.
- [Building from source](./become-a-validator-source.md): this is a little more involved, however it
   gives a more hands-on experience.

Once you have completed **only one** of these steps, move onto the next step.

## 2. Submit your deposit to Goerli

<div class="form-signin" id="uploadDiv">
	<p>Upload the <code>eth1_deposit_data.rlp</code> file from your validator
	directory (created in Step 1) to submit your 3.2 Goerli-ETH
	deposit using Metamask.</p>
	<p>Hint: the method used in Step 1 will determine where this file is
	located.</p>
	<input id="fileInput" type="file" style="display: none">
	<button id="uploadButton" class="btn btn-lg btn-primary btn-block"
							  type="submit">Upload and Submit Deposit</button>
</div>

<div class="form-signin" id="waitingDiv" style="display: none">
	<p>Your validator deposit was submitted and this step is complete.</p>
	<p>See the transaction on <a id="txLink" target="_blank"
											 href="https://etherscan.io">Etherscan</a>
	or <a href="">reload</a> to perform another deposit.</p>
</div>

<div class="form-signin" id="errorDiv" style="display: none">
	<h4 class="h3 mb-3 font-weight-normal">Error</h4>
	<p id="errorText">Unknown error.</p>
</div>

> This deposit is using gETH (Goerli ETH) which has no real value. Don't ever
> send _real_ ETH to our deposit contract!

## 3. Leave Lighthouse running

Leave your beacon node and validator client running and you'll see logs as the
beacon node keeps synced with the network and the validator client produces
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


<script src="https://ajax.googleapis.com/ajax/libs/jquery/1.11.1/jquery.min.js"></script>
<script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js"></script>
<script charset="utf-8"
		src="https://cdn.ethers.io/scripts/ethers-v4.min.js"
		type="text/javascript">
</script>
<script src="js/deposit.js"></script>
