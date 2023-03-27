# Configuration

Siren requires a connection to both a Lighthouse Validator Client
and a Lighthouse Beacon Node. Upon running you will first be greeted by the
following configuration screen.

![ui-configuration](./imgs/ui-configuration.png)


## Connecting to the Clients

This allows you to enter the address and ports of the associated Lighthouse
Beacon node and Lighthouse Validator client.

> The Beacon Node must be run with the `--gui` flag set. To allow the browser
> to access the node beyond your local computer you also need to allow CORS in
> the http API. This can be done via `--http-allow-origin "*"`.

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

The contents of this file for the desired valdiator client needs to be
entered.

## Name

This is your name, it can be modified and is solely used for aesthetics. 

## Device

This is a name that can be associated with the validator client/beacon
node pair. Multiple such pairs can be remembered for quick swapping between
them.
