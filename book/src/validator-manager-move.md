# Moving Validators

The `lighthouse validator-manager move` command uses the VC HTTP API to move
validators from one VC (the "src" VC) to another VC (the "dest" VC). The move
operation is *comprehensive*; it will:

- Disable the validators the src VC.
- Remove the validator keystores from the src VC file system.
- Export the slashing database records for the appropriate validators from the src VC to the dest VC.
- Enable the validators on the dest VC.
- Generally result in very little or no validator downtime.

It is capable of moving all validators on the src VC, a number of validators or
specific validators from one VC to another.

The `move` command is only guaranteed to work between two Lighthouse VCs (i.e.,
there is no guarantee that the commands will work between Lighthouse and Teku or
another client).

The `move` command only supports moving validators using a keystore on the local
file system, it does not support `Web3Signer` validators.

Although all efforts are taken to avoid it, it's possible for the `move` command
to fail in a way removes the validator from the src VC without adding it to the
dest VC. Therefore, it is recommended to **never use the `move` command without
having a backup of all validator keystores (e.g., the mnemonic).**

## Simple Example

The following command will move all validators from the VC running at
`http://localhost:6062` to the VC running at `http://localhost:5062`.

```
lighthouse \
	validator-manager \
	move \
	--src-vc-url http://localhost:6062 \
	--src-vc-token ~/src-token.txt \
	--dest-vc-url http://localhost:5062 \
	--dest-vc-token ~/.lighthouse/mainnet/validators/api-token.txt \
	--validators all \
```

## Detailed Guide

This guide describes the steps to move validators between two validator clients (VCs) which are
able to SSH between each other. This guide assumes experience with the Linux command line and SSH
connections.

There will be two VCs in this example:

- The *source* VC which contains the validators/keystores to be moved.
- The *destination* VC which is to take the validators/keystores from the source.

The example will assume the source VC is accessible at `src-host` and the destination VC is
accessible at `dest-host`. Replace these values with your own hostnames or IP addresses.

The example assumes that the reader is currently logged into `dest-host` via SSH
and that the reader can SSH from `dest-host` to `src-host`.

### 1. Configure the Source VC

The source VC needs to have the following flags at a mininum:

- `--http`
- `--unencrypted-http-transport`
- `--http-address 127.0.0.1`
- `--http-port 5062`
- `--http-allow-keystore-export`

Therefore, the source VC command might look like:

```bash
lighthouse \
    vc \
    --http \
    --unencrypted-http-transport \
    --http-address 127.0.0.1 \
    --http-port 5062 \
    --http-allow-keystore-export
```

### 2. Configure the Destination VC

The destination VC needs to have the following flags at a mininum:

- `--http`
- `--unencrypted-http-transport`
- `--http-address 127.0.0.1`
- `--http-port 5062`
- `--enable-doppelganger-protection`

Therefore, the destination VC command might look like:

```bash
lighthouse \
    vc \
    --http \
    --unencrypted-http-transport \
    --http-address 127.0.0.1 \
    --http-port 5062 \
    --enable-doppelganger-protection
```

The `--enable-doppelganger-protection` flag is not *strictly* required, however
it is recommended for an additional layer of safety. It will result in 3-4
epochs of downtime for the validator after it is moved, which is generally an
inconsequential cost in lost rewards or penalties.

Optionally, users can add the `--http-store-passwords-in-secrets-dir` flag if they'd like to have
the import validator keystore passwords stored in separate files rather than in the
`valdiator-definitions.yml` file. If you don't know what this means, you can safely omit the flag.

### 3. Configure SSH

For this example to work, the `dest-host` host must be able to SSH to the `src-host` host. This
configuration is out-of-scope of this article, however it probably involves adding a public key to
the `.ssh/authorized_keys` file on the `dest-host` host.

You will know this is complete when you can SSH to the `dest-host` from your PC and then run `ssh
src-host` successfully.

### 4. Obtain the Source API Token

The VC API is protected by an *API token*. This is stored in a file on each of the hosts. Since
we'll be running our command on the destination host, it will need to have the API token for the
source host on its file-system.

On the **source host**, find the location of the `api-token.txt` file and copy the contents. The
location of the file varies, but it is located in the "validator directory" of your data directory,
alongside validator keystores. For example: `~/.lighthouse/mainnet/validators/api-token.txt`.

Copy the contents of that file into a new file on the **destination host** at `~/src-token.txt`. The
API token should be similar to `api-token-0x03eace4c98e8f77477bb99efb74f9af10d800bd3318f92c33b719a4644254d4123`.

### 4. Create an SSH Tunnel

In one terminal window, SSH to the **destination host** and establish a reverse-SSH connection
between the **desination host** and the **source host**.

```bash
ssh dest-host
ssh -L 6062:localhost:5062 src-host
```

It's important that you leave this session open throughout the rest of this tutorial. If you close
this terminal window then the connection between the destination and source host will be lost.

### 5. Move

With the SSH tunnel established between the `dest-host` and `src-host`, from the **destination
host** run the command to move the validators:

```
lighthouse \
	validator-manager \
	move \
	--src-vc-url http://localhost:6062 \
	--src-vc-token ~/src-token.txt \
	--dest-vc-url http://localhost:5062 \
	--dest-vc-token ~/.lighthouse/mainnet/validators/api-token.txt \
	--validators all \
```

The command will provide information about the progress of the operation and
emit `Done.` when the operation has completed successfully.

Once the operation completes successfully, there is nothing else to be done. The
validators have been removed from the `src-host` and enabled at the `dest-host`.
If the `--enable-doppelganger-protection` flag was used it may take 3-4 epochs
for the validators to start attesting and producing blocks on the `dest-host`.

Any errors encounted during the operation should include information on how to
proceed. Assistance is also available on our
[Discord](https://discord.gg/cyAszAh).