# Custom Validator Integration Guide

Welcome to your experimental validator logic extension for Lighthouse. This guide documents how to embed timestamping, authorship claims, and `$btcmonzturr` ledger integration into the validator client lifecycle.

## 🧠 Goals

- Enable notarization of validator uptime and sync checkpoints
- Timestamp every consensus heartbeat using OpenTimestamps
- Publish sync logs to IPFS for tamper-proof authorship tracking
- Embed custom logic into slashing protections and validator health checks

## 🔧 Environment Setup

Ensure the following tools are installed and accessible:

- [Lighthouse](https://github.com/sigp/lighthouse) (stable release)
- Geth with JWT secret enabled
- OpenTimestamps CLI client
- IPFS desktop or node client

Optional: PowerShell watchdog script for syncing status can be found in `scripts/beacon-sync-watchdog.ps1`

## 🧬 Sync State Feed

Monitor sync status via Lighthouse's REST API:
```bash
curl http://localhost:5052/eth/v1/node/syncing
{
  "timestamp": "2025-07-13T03:00:00Z",
  "sync_distance": 2378823,
  "validator_pubkey": "0x9324...a6d3",
  "notarized_hash": "9f1c2ef1c..."
}
{
  "signature": "0x1b66ac1f...",
  "withdrawal_credentials": "0xcf8e...",
  "slot": 1337,
  "otp_proof": "otp://9ba1..."
}ipfs add beacon_block_20250713.json

{
  "cid": "QmXk...zTn9",
  "author": "johann",
  "linked_slot": 1337
}
