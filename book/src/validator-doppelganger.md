# Doppelganger Protection

[doppelgänger]: https://en.wikipedia.org/wiki/Doppelg%C3%A4nger
[Slashing Protection]: ./slashing-protection.md
[VC HTTP API]: ./api-vc.md

From Lighthouse `v1.5.0`, the *Doppelganger Protection* feature is available for the Validator
Client. Taken from the German *[doppelgänger]*, which translates literally to "double-walker", a
"doppelganger" in Eth2 refers to another instance of a validator running on a separate validator
service. As detailed in [Slashing Protection], running the same validator twice will inevitably
result in slashing.

The Doppelganger Protection (DP) feature in Lighthouse *imperfectly* attempts to detect other
instances of a validator operating on the network before any slashable offences can be committed. It
achieves this by waiting 2-3 epochs after a validator is started to other messages from other
processes from that validator before starting to sign and publish slashable messages.

## Considerations

There are two important considerations when using DP:

### 1. Doppelganger Protection is imperfect

The mechanism is best-effort and imperfect. Even if another validator exists on the network, there
is no guarantee that your Beacon Node (BN) will see messages from it. **It is feasible for
doppelganger protection to fail to detect another validator due to network faults or other common
circumstances.**

DP should be considered a last-line-of-defence that *might* save a validator from being slashed due
to operator error (the error being running two instances of the same validator). Users should
*never* rely upon DP and should practice the same caution with regards to duplicating validators as
if it did not exist.

### 2. Using Doppelganger Protection will always result in penalties

DP works by staying silent on the network for 2-3 epochs before starting to sign slashable messages.
Staying silent and refusing to sign messages will cause the following:

- 2-3 missed attestations, incurring penalties and missed rewards)
- 2-3 epochs of missed sync committee contributions, incurring penalties and missed rewards.
    (Post-Altair upgrade only)
- Potentially missed rewards by missing a block proposal (generally very unlikely for one
    validator).

The loss of rewards and penalties incurred due to the missed duties will be very small in
dollar-values. Generally, they will equate around one US dollar (at August 2021 figures) or about 2%
of daily validator rewards. Since DP costs so little but can protect a user from slashing, many
users will consider this a worthwhile trade-off.

The 2-3 epochs of missed duties will be incurred whenever the VC is started (e.g., after an update
or reboot) or whenever a new validator is added via the [VC HTTP API].

## Enabling Doppelganger Protection

If you understand that DP is imperfect and will cause some (generally, non-substantial) missed
duties, it can be enabled by providing the `--enable-doppelganger-protection` flag:

```bash
lighthouse vc --enable-doppelganger-protection
```
