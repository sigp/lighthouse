# Doppelganger Protection

[doppelgänger]: https://en.wikipedia.org/wiki/Doppelg%C3%A4nger
[Slashing Protection]: ./slashing-protection.md
[VC HTTP API]: ./api-vc.md

From Lighthouse `v1.5.0`, the *Doppelganger Protection* feature is available for the Validator
Client. Taken from the German *[doppelgänger]*, which translates literally to "double-walker", a
"doppelganger" in Eth2 refers to another instance of a validator running in a separate validator
process. As detailed in [Slashing Protection], running the same validator twice will inevitably
result in slashing.

The Doppelganger Protection (DP) feature in Lighthouse *imperfectly* attempts to detect other
instances of a validator operating on the network before any slashable offences can be committed. It
achieves this by staying silent for 2-3 epochs after a validator is started so it can listen for
other instances of that validator before starting to sign potentially slashable messages.

> Note: Doppelganger Protection is not yet interoperable, so if it is configured on a Lighthouse
> validator client, the client must be connected to a Lighthouse beacon node. Because Infura
> uses Teku, Lighthouse's Doppelganger Protection cannot yet be used with Infura's Eth2 service.

## Initial Considerations

There are two important initial considerations when using DP:

### 1. Doppelganger Protection is imperfect

The mechanism is best-effort and imperfect. Even if another validator exists on the network, there
is no guarantee that your Beacon Node (BN) will see messages from it. **It is feasible for
doppelganger protection to fail to detect another validator due to network faults or other common
circumstances.**

DP should be considered a last-line-of-defence that *might* save a validator from being slashed due
to operator error (i.e. running two instances of the same validator). Users should
*never* rely upon DP and should practice the same caution with regards to duplicating validators as
if it did not exist.

**Remember: even with doppelganger protection enabled, it is not safe to run two instances of the
same validator.**

### 2. Using Doppelganger Protection will always result in penalties

DP works by staying silent on the network for 2-3 epochs before starting to sign slashable messages.
Staying silent and refusing to sign messages will cause the following:

- 2-3 missed attestations, incurring penalties and missed rewards.
- 2-3 epochs of missed sync committee contributions (if the validator is in a sync committee, which is unlikely), incurring penalties and missed rewards (post-Altair upgrade only).
- Potentially missed rewards by missing a block proposal (if the validator is an elected block
    proposer, which is unlikely).

The loss of rewards and penalties incurred due to the missed duties will be very small in
dollar-values. Generally, they will equate to around one US dollar (at August 2021 figures) or about
2% of the reward for one validator for one day. Since DP costs so little but can protect a user from
slashing, many users will consider this a worthwhile trade-off.

The 2-3 epochs of missed duties will be incurred whenever the VC is started (e.g., after an update
or reboot) or whenever a new validator is added via the [VC HTTP API].

## Enabling Doppelganger Protection

If you understand that DP is imperfect and will cause some (generally, non-substantial) missed
duties, it can be enabled by providing the `--enable-doppelganger-protection` flag:

```bash
lighthouse vc --enable-doppelganger-protection
```

When enabled, the validator client will emit the following log on start up:

```
INFO Doppelganger detection service started  service: doppelganger
```

Whilst DP is active, the following log will be emitted (this log indicates that one validator is
staying silent and listening for validators):

```
INFO Listening for doppelgangers     doppelganger_detecting_validators: 1, service: notifier
```

When a validator has completed DP without detecting a doppelganger, the following log will be
emitted:

```
INFO Doppelganger protection complete   validator_index: 42, msg: starting validator, service: notifier
```

## What if a doppelganger is detected?

If a doppelganger is detected, logs similar to those below will be emitted (these logs indicate that
the validator with the index `42` was found to have a doppelganger):

```
CRIT Doppelganger(s) detected                doppelganger_indices: [42], msg: A doppelganger occurs when two different validator clients run the same public key. This validator client detected another instance of a local validator on the network and is shutting down to prevent potential slashable offences. Ensure that you are not running a duplicate or overlapping validator client, service: doppelganger
INFO Internal shutdown received              reason: Doppelganger detected.
INFO Shutting down..                         reason: Failure("Doppelganger detected.")
```

Observing a doppelganger is a serious problem and users should be *very alarmed*. The Lighthouse DP
system tries very hard to avoid false-positives so it is likely that a slashing risk is present.

If a doppelganger is observed, the VC will shut down. **Do not restart the VC until you are certain
there is no other instance of that validator running elsewhere!**

The steps to solving a doppelganger vary depending on the case, but some places to check are:

1. Is there another validator process running on this host?
    - Unix users can check `ps aux | grep lighthouse`
    - Windows users can check the Task Manager.
1. Has this validator recently been moved from another host? Check to ensure it's not running.
1. Has this validator been delegated to a staking service?

## Doppelganger Protection FAQs

### Should I use DP?

Yes, probably. If you don't have a clear and well considered reason *not* to use DP, then it is a
good idea to err on the safe side.

### How long does it take for DP to complete?

DP takes 2-3 epochs, which is approximately 12-20 minutes.

### How long does it take for DP to detect a doppelganger?

To avoid false positives from restarting the same VC, Lighthouse will wait until the next epoch
before it starts detecting doppelgangers. Additionally, a validator might not attest till the end
of the next epoch. This creates a 2 epoch delay, which is just over 12 minutes. Network delays or
issues might lengthen this time more.

This means your validator client might take up to 20 minutes to detect a doppelganger and shut down.

### Can I use DP to run redundant validator instances?

🙅 **Absolutely not.** 🙅 DP is imperfect and cannot be relied upon. The Internet is messy and lossy,
there's no guarantee that DP will detect a duplicate validator before slashing conditions arise.
