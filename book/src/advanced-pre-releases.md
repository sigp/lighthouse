# Pre-Releases

[sigp/lighthouse]: https://github.com/sigp/lighthouse
[sigp/lighthouse/releases/latest]: https://github.com/sigp/lighthouse/releases/latest
[sigp/lighthouse/releases]: https://github.com/sigp/lighthouse/releases
[`v1.4.0-rc.0`]: https://github.com/sigp/lighthouse/releases/tag/v1.4.0-rc.0
[`v1.4.0`]: https://github.com/sigp/lighthouse/releases/tag/v1.4.0

From time-to-time, Lighthouse *pre-releases* will be published on the [sigp/lighthouse] repository.
These releases have passed the usual automated testing, however the developers would like to see it
running "in the wild" in a variety of configurations before declaring it an official, stable
release. Pre-releases are also used by developers to get feedback from users regarding the
ergonomics of new features or changes.

Github will clearly show such releases as a "Pre-release" and they *will not* show up on
[sigp/lighthouse/releases/latest]. However, pre-releases *will* show up on the
[sigp/lighthouse/releases] page, so **please pay attention to avoid the pre-releases when you're
looking for stable Lighthouse**.

### Examples

[`v1.4.0-rc.0`] has `rc` (release candidate) in the version string and is therefore a pre-release. This
release is *not* stable and is *not* intended for critical tasks on mainnet (e.g., staking).

However, [`v1.4.0`] is considered stable since it is not marked as a pre-release and does not
contain `rc` in the version string. This release is intended for use on mainnet.

## When to use a pre-release

Users may wish to try a pre-release for the following reasons:

- To preview new features before they are officially released.
- To help detect bugs and regressions before they reach production.
- To provide feedback on annoyances before they make it into a release and become harder to change or revert.

## When *not* to use a pre-release

It is not recommended to use pre-releases for any critical tasks on mainnet (e.g., staking). To test
critical features, try one of the testnets (e.g., Prater).

