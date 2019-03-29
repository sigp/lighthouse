# Lighthouse Accounts Manager

The accounts manager (AM) is a stand-alone binary which allows
users to generate and manage the cryptographic keys necessary to
interact with Ethereum Serenity.

## Roles

The AM is responsible for the following tasks:
- Generation of cryptographic key pairs
  - Must acquire sufficient entropy to ensure keys are generated securely (TBD)
- Secure storage of private keys
  - Keys must be encrypted while at rest on the disk (TBD)
  - The format is compatible with the validator client
- Produces messages and transactions necessary to initiate
staking on Ethereum 1.x (TPD)


## Implementation

The AM is not a service, and does not run continuously, nor does it
interact with any running services.
It is intended to be executed separately from other Lighthouse binaries
and produce files which can be consumed by them.