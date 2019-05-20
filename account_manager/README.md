# Lighthouse Account Manager

The account manager (AM) is a stand-alone binary which allows
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
and produce files which can be consumed by them.&

## Usage

Simply run `./account_manager generate` to generate a new random private key,
which will be automatically saved to the correct directory.

If you prefer to use our "deterministic" keys for testing purposes, simply
run `./accounts_manager generate_deterministic -i <index>`, where `index` is
the validator index for the key. This will reliably produce the same key each time
and save it to the directory.