# Configuration

Siren requires a connection to both a Lighthouse Validator Client
and a Lighthouse Beacon Node. Upon running you will first be greeted by the
following configuration screen.

![ui-configuration](./imgs/ui-configuration.png)


## Connecting to the Clients

This allows you to enter the address and ports of the associated Lighthouse
Beacon node and Lighthouse Validator client.

> The Beacon Node must be run with the `--gui` flag set. 

If you run Siren in the browser (by entering `localhost` in the browser), you will need to allow CORS in the HTTP API. This can be done by adding the flag `--http-allow-origin "*"` for both beacon node and validator client. If you would like to access Siren beyond the local computer, we recommend using an SSH tunnel. This requires a tunnel for 3 ports: `80` (assuming the port is unchanged as per the [installation guide](./ui-installation.md#docker-recommended), `5052` (for beacon node) and `5062` (for validator client). You can use the command below to perform SSH tunneling:
```bash
ssh -N -L 80:127.0.0.1:80 -L 5052:127.0.0.1:5052 -L 5062:127.0.0.1:5062 username@local_ip
```  

where `username` is the username of the server and `local_ip` is the local IP address of the server. Note that with the `-N` option in an SSH session, you will not be able to execute commands in the CLI to avoid confusion with ordinary shell sessions. The connection will appear to be "hung" upon a successful connection, but that is normal. Once you have successfully connected to the server via SSH tunneling, you should be able to access Siren by entering `localhost` in a web browser. 

You can also access Siren using the app downloaded in the [Siren release page](https://github.com/sigp/siren/releases). To access Siren beyond the local computer, you can use SSH tunneling for ports `5052` and `5062` using the command:

```bash
ssh -N -L 5052:127.0.0.1:5052 -L 5062:127.0.0.1:5062 username@local_ip
```  

A green tick will appear once Siren is able to connect to both clients. You
can specify different ports for each client by clicking on the advanced tab.


## API Token

The API Token is a secret key that allows you to connect to the validator
client. The validator client's HTTP API is guarded by this key because it
contains sensitive validator information and the ability to modify
validators. Please see [`Validator Authorization`](./api-vc-auth-header.md)
for further details. 

Siren requires this token in order to connect to the Validator client.
The token is located in the default data directory of the validator
client. The default path is
`~/.lighthouse/<network>/validators/api-token.txt`.

The contents of this file for the desired validator client needs to be
entered.

## Name

This is your name, it can be modified and is solely used for aesthetics. 

## Device

This is a name that can be associated with the validator client/beacon
node pair. Multiple such pairs can be remembered for quick swapping between
them.
