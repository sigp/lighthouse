const NETWORK = "5";
const NETWORK_NAME = "Goerli Test Network";
const DEPOSIT_CONTRACT = "0x13e4d66c7215d7b63fec7b52fc65e6655093d906";
const DEPOSIT_AMOUNT_ETH = "3.2";
const GAS_LIMIT = "4000000";
const DEPOSIT_DATA_BYTES = 420;

let PREVIOUS_NON_ERROR_STATE = "";

$(document).ready(function(){
	if (typeof window.ethereum !== 'undefined') {
		ethereum.on('networkChanged', function (accounts) {
			checkNetwork()
		})

		PREVIOUS_NON_ERROR_STATE = "upload";
		checkNetwork()
	} else {
		console.error("No metamask detected!")
		triggerError("Metamask is not installed.<br> <a href='https://metamask.io'>Get Metamask.</a>")
	}

	$("#fileInput").change(function() {
			openFile(this.files[0])
	});

	$("#uploadButton").on("click", function() {
		$("#fileInput").trigger("click");
	});
});

function checkNetwork() {
		if (window.ethereum.networkVersion === NETWORK) {
			setUiState(PREVIOUS_NON_ERROR_STATE)
		} else {
			triggerError("Please set Metamask to use " + NETWORK_NAME + ".")
		}
}

function doDeposit(deposit_data) {
	const ethereum = window.ethereum;
	const utils = ethers.utils;

	let wei = utils.parseEther(DEPOSIT_AMOUNT_ETH);
	let gasLimit = utils.bigNumberify(GAS_LIMIT);

	ethereum.enable()
		.then(function (accounts) {
			let params = [{
				"from": accounts[0],
				"to": DEPOSIT_CONTRACT,
				"gas": utils.hexlify(gasLimit),
				"value": utils.hexlify(wei),
				"data": deposit_data
			}]

			ethereum.sendAsync({
				method: 'eth_sendTransaction',
				params: params,
				from: accounts[0], // Provide the user's account to use.
			}, function (err, result) {
				if (err !== null) {
					triggerError("<p>" + err.message + "</p><p><a href=''>Reload</a> the window to try again.</p>")
				} else {
					let tx_hash = result.result;
					$("#txLink").attr("href", "https://goerli.etherscan.io/tx/" + tx_hash);
					setUiState("waiting");
				}
			})
		})
		.catch(function (error) {
			triggerError("Unable to get Metamask accounts.<br>Reload page to try again.")
		})

}

function openFile(file) {
  var reader = new FileReader();

	reader.onload = function () {
		let data = reader.result;
		if (data.startsWith("0x")) {
			if (data.length === DEPOSIT_DATA_BYTES * 2 + 2) {
				doDeposit(data)
			} else {
				triggerError("Invalid eth1_deposit_file. Bad length.")
			}
		} else {
			triggerError("Invalid eth1_deposit_file. Did not start with 0x.")
		}
  }

  reader.readAsBinaryString(file);
}

function triggerError(text) {
	$("#errorText").html(text);
	setUiState("error");
}

function setUiState(state) {
	if (state === "upload") {
		$('#uploadDiv').show();
		$('#depositDiv').hide();
		$('#waitingDiv').hide();
		$('#errorDiv').hide();
	} else if (state == "deposit") {
		$('#uploadDiv').hide();
		$('#depositDiv').show();
		$('#waitingDiv').hide();
		$('#errorDiv').hide();
	} else if (state == "error") {
		$('#uploadDiv').hide();
		$('#depositDiv').hide();
		$('#waitingDiv').hide();
		$('#errorDiv').show();
	} else if (state == "waiting") {
		$('#uploadDiv').hide();
		$('#depositDiv').hide();
		$('#waitingDiv').show();
		$('#errorDiv').hide();
	}

	if (state !== "error") {
		PREVIOUS_NON_ERROR_STATE = state;
	}
}
