# List Validators

The `lighthouse validator-manager list` command shows a list of all the validators
on a validator

## Example

Here we are listing the validators on a Lighthouse VC locally using localhost:
```bash
$ l"ighthouse validator-manager list --vc-token ~/data/lighthouse/mainnet/validators/api-token.txt --vc-url http://localhost:5062"
Running validator manager for mainnet network
Validator client is reachable at http://localhost:5062/ and reports 3 validators
  0: ValidatorData { enabled: true, description: "", voting_pubkey: 0xa42c79bb8b...5096432170e281a }
  1: ValidatorData { enabled: true, description: "", voting_pubkey: 0xa5e8c91eff...c97198a58894e60 }
  2: ValidatorData { enabled: true, description: "", voting_pubkey: 0xafa1b94d2a...ba4276802c2bd3c }
  3: ValidatorData { enabled: true, description: "", voting_pubkey: 0xb93730fea6...0769883f8fde6f2 }
```

But assuming the Lighthouse VC is available on your local network and you've copied the api-token
to the device your issuing the `list` command from, then you can also list via its IP address.
```bash
$ lighthouse vm list --vc-token ~/api-tokens/192.168.1.12-api-token.txt --vc-url http://192.168.1.12:5062"
Running validator manager for mainnet network
Validator client is reachable at http://localhost:5062/ and reports 3 validators
  0: ValidatorData { enabled: true, description: "", voting_pubkey: 0xa42c79bb8b...5096432170e281a }
  1: ValidatorData { enabled: true, description: "", voting_pubkey: 0xa5e8c91eff...c97198a58894e60 }
  2: ValidatorData { enabled: true, description: "", voting_pubkey: 0xafa1b94d2a...ba4276802c2bd3c }
  3: ValidatorData { enabled: true, description: "", voting_pubkey: 0xb93730fea6...0769883f8fde6f2 }
```

> Note: as a shortcut you can refer to the `validator-manager` using `vm` as seen above.
