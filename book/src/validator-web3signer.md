# Remote Signing with Web3Signer

[Web3Signer]: https://docs.web3signer.consensys.net/en/latest/
[Consensys]: https://github.com/ConsenSys/
[Teku]: https://github.com/consensys/teku

[Web3Signer] is a tool by Consensys which allows *remote signing*. Remote signing is when a
Validator Client (VC) out-sources the signing of messages to remote server (e.g., via HTTPS). This
means that the VC does not hold the validator private keys.

## Warnings

Using a remote signer comes with risks, please read the following two warnings before proceeding:

### Remote signing is complex and risky

Remote signing is generally only desirable for enterprise users or users with unique security
requirements. Most users will find the separation between the Beacon Node (BN) and VC to be
sufficient *without* introducing a remote signer.

**Using a remote signer introduces a new set of security and slashing risks and should only be
undertaken by advanced users who fully understand the risks.**

### Web3Signer is not maintained by Lighthouse

The [Web3Signer] tool is maintained by [Consensys], the same team that maintains [Teku]. The
Lighthouse team (Sigma Prime) does not maintain Web3Signer or make any guarantees about its safety
or effectiveness.

## Usage

A remote signing validator is added to Lighthouse in much the same way as one that uses a local
keystore, via the [`validator_definitions.yml`](./validator-management.md) file or via the `POST
/lighthouse/validators/web3signer` API endpoint.

Here is an example of a `validator_definitions.yml` file containing one validator which uses a
remote signer:

```yaml
---
- enabled: true
  voting_public_key: "0xa5566f9ec3c6e1fdf362634ebec9ef7aceb0e460e5079714808388e5d48f4ae1e12897fed1bea951c17fa389d511e477"
  type: web3signer
  url: "https://my-remote-signer.com:1234"
  root_certificate_path: /home/paul/my-certificates/my-remote-signer.pem
```

When using this file, the Lighthouse VC will perform duties for the `0xa5566..` validator and defer
to the `https://my-remote-signer.com:1234` server to obtain any signatures. It will load a
"self-signed" SSL certificate from `/home/paul/my-certificates/my-remote-signer.pem` (on the
filesystem of the VC) to encrypt the communications between the VC and Web3Signer.

> The `request_timeout_ms` key can also be specified. Use this key to override the default timeout
> with a new timeout in milliseconds. This is the timeout before requests to Web3Signer are
> considered to be failures. Setting a value that it too-long may create contention and late duties
> in the VC.  Setting it too short will result in failed signatures and therefore missed duties.
