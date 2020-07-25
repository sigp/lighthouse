# Submit Medalla Validator Deposit

Use Metamask to submit your deposit to become a validator on the Eth2 Medalla
**testnet**.

**Only ever send Goerli ETH to the Medalla deposit contract.**

<div class="form-signin" id="uploadDiv">
	<p>Upload the <code>eth1_deposit_data.rlp</code> file from your validator
	directory (created in the previous step) to submit your 3.2 Goerli-ETH
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

<script src="https://ajax.googleapis.com/ajax/libs/jquery/1.11.1/jquery.min.js"></script>
<script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js"></script>
<script charset="utf-8"
		src="https://cdn.ethers.io/scripts/ethers-v4.min.js"
		type="text/javascript">
</script>
<script src="js/deposit-via-url.js"></script>
