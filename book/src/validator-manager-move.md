# Moving Validators

This document describes the steps to move validators between two validator clients (VCs) which are
able to SSH between each other. This guides assumes experience with the Linux command line and SSH
connections.

There will be two VCs in this example:

- The *source* VC which contains the validators/keystores to be moved.
- The *destination* VC which is to take the validators/keystores from the source.

This example will assume the source VC is accessible at `src-host` and the destination VC is
accessible at `dest-host`. Replace these values with your own.

### 1. Configure the Source VC

The source VC needs to have the following flags:

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

The destination VC needs to have the following flags:

```bash
lighthouse \
    vc \
    --http \
    --unencrypted-http-transport \
    --http-address 127.0.0.1 \
    --http-port 5062 \
```

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

TODO
