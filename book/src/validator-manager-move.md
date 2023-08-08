# Moving Validators

The `lighthouse validator-manager move` command uses the VC HTTP API to move
validators from one VC (the "src" VC) to another VC (the "dest" VC). The move
operation is *comprehensive*; it will:

- Disable the validators on the src VC.
- Remove the validator keystores from the src VC file system.
- Export the slashing database records for the appropriate validators from the src VC to the dest VC.
- Enable the validators on the dest VC.
- Generally result in very little or no validator downtime.

It is capable of moving all validators on the src VC, a count of validators or
a list of pubkeys.

The `move` command is only guaranteed to work between two Lighthouse VCs (i.e.,
there is no guarantee that the commands will work between Lighthouse and Teku, for instance).

The `move` command only supports moving validators using a keystore on the local
file system, it does not support `Web3Signer` validators.

Although all efforts are taken to avoid it, it's possible for the `move` command
to fail in a way that removes the validator from the src VC without adding it to the
dest VC. Therefore, it is recommended to **never use the `move` command without
having a backup of all validator keystores (e.g. the mnemonic).**

## Simple Example

The following command will move all validators from the VC running at
`http://localhost:6062` to the VC running at `http://localhost:5062`.

```bash
lighthouse \
	validator-manager \
	move \
	--src-vc-url http://localhost:6062 \
	--src-vc-token ~/src-token.txt \
	--dest-vc-url http://localhost:5062 \
	--dest-vc-token ~/.lighthouse/mainnet/validators/api-token.txt \
	--validators all
```

## Detailed Guide

This guide describes the steps to move validators between two validator clients (VCs) which are
able to SSH between each other. This guide assumes experience with the Linux command line and SSH
connections.

There will be two VCs in this example:

- The *source* VC which contains the validators/keystores to be moved.
- The *destination* VC which is to take the validators/keystores from the source.

There will be two hosts in this example:

- Host 1 (*"source host"*): Is running the `src-vc`.
- Host 2 (*"destination host"*): Is running the `dest-vc`.

The example assumes
that Host 1 is able to SSH to Host 2.

In reality, many host configurations are possible. For example:

- Both VCs on the same host.
- Both VCs on different hosts and the `validator-manager` being used on a third host.

### 1. Configure the Source VC

The source VC needs to have the following flags at a minimum:

- `--http`
- `--http-port 5062`
- `--http-allow-keystore-export`

Therefore, the source VC command might look like:

```bash
lighthouse \
    vc \
    --http \
    --http-port 5062 \
    --http-allow-keystore-export
```

### 2. Configure the Destination VC

The destination VC needs to have the following flags at a minimum:

- `--http`
- `--http-port 5062`
- `--enable-doppelganger-protection`

Therefore, the destination VC command might look like:

```bash
lighthouse \
    vc \
    --http \
    --http-port 5062 \
    --enable-doppelganger-protection
```

> The `--enable-doppelganger-protection` flag is not *strictly* required, however
> it is recommended for an additional layer of safety. It will result in 2-3
> epochs of downtime for the validator after it is moved, which is generally an
> inconsequential cost in lost rewards or penalties.
> 
> Optionally, users can add the `--http-store-passwords-in-secrets-dir` flag if they'd like to have
> the import validator keystore passwords stored in separate files rather than in the
> `validator-definitions.yml` file. If you don't know what this means, you can safely omit the flag.

### 3. Obtain the Source API Token

The VC API is protected by an *API token*. This is stored in a file on each of the hosts. Since
we'll be running our command on the destination host, it will need to have the API token for the
source host on its file-system.

On the **source host**, find the location of the `api-token.txt` file and copy the contents. The
location of the file varies, but it is located in the "validator directory" of your data directory,
alongside validator keystores. For example: `~/.lighthouse/mainnet/validators/api-token.txt`. If you are unsure of the `api-token.txt` path, you can run `curl http://localhost:5062/lighthouse/auth` which will show the path.

Copy the contents of that file into a new file on the **destination host** at `~/src-token.txt`. The
API token should be similar to `api-token-0x03eace4c98e8f77477bb99efb74f9af10d800bd3318f92c33b719a4644254d4123`.

### 4. Create an SSH Tunnel

In the **source host**, open a terminal window, SSH to the **destination host** and establish a reverse-SSH connection
between the **destination host** and the **source host**.

```bash
ssh dest-host
ssh -L 6062:localhost:5062 src-host
```

It's important that you leave this session open throughout the rest of this tutorial. If you close
this terminal window then the connection between the destination and source host will be lost.

### 5. Move

With the SSH tunnel established between the `dest-host` and `src-host`, from the **destination
host** run the command to move the validators:

```bash
lighthouse \
	validator-manager \
	move \
	--src-vc-url http://localhost:6062 \
	--src-vc-token ~/src-token.txt \
	--dest-vc-url http://localhost:5062 \
	--dest-vc-token ~/.lighthouse/mainnet/validators/api-token.txt \
	--validators all
```

The command will provide information about the progress of the operation and
emit `Done.` when the operation has completed successfully. For example:

```bash
Running validator manager for mainnet network
Validator client is reachable at http://localhost:5062/ and reports 2 validators
Validator client is reachable at http://localhost:6062/ and reports 0 validators
Moved keystore 1 of 2
Moved keystore 2 of 2
Done.
```
At the same time, `lighthouse vc` will log:
```bash
INFO Importing keystores via standard HTTP API, count: 1
INFO Enabled validator                       voting_pubkey: 0xab6e29f1b98fedfca878edce2b471f1b5ee58ee4c3bd216201f98254ef6f6eac40a53d74c8b7da54f51d3e85cacae92f, signing_method: local_keystore
INFO Modified key_cache saved successfully
Once the operation completes successfully, there is nothing else to be done. The
validators have been removed from the `src-host` and enabled at the `dest-host`.
If the `--enable-doppelganger-protection` flag was used it may take 2-3 epochs
for the validators to start attesting and producing blocks on the `dest-host`.
If you would only like to move some validators, you can replace the flag `--validators all` with one or more validator public keys. For example:

```bash
lighthouse \
	validator-manager \
	move \
	--src-vc-url http://localhost:6062 \
	--src-vc-token ~/src-token.txt \
	--dest-vc-url http://localhost:5062 \
	--dest-vc-token ~/.lighthouse/mainnet/validators/api-token.txt \
	--validators 0x9096aab771e44da149bd7c9926d6f7bb96ef465c0eeb4918be5178cd23a1deb4aec232c61d85ff329b54ed4a3bdfff3a,0x90fc4f72d898a8f01ab71242e36f4545aaf87e3887be81632bb8ba4b2ae8fb70753a62f866344d7905e9a07f5a9cdda1
```
Any errors encountered during the operation should include information on how to
proceed. Assistance is also available on our
[Discord](https://discord.gg/cyAszAh).