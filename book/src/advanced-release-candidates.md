# Release Candidates

[sigp/lighthouse]: https://github.com/sigp/lighthouse
[sigp/lighthouse/releases/latest]: https://github.com/sigp/lighthouse/releases/latest
[sigp/lighthouse/releases]: https://github.com/sigp/lighthouse/releases
[`v1.4.0-rc.0`]: https://github.com/sigp/lighthouse/releases/tag/v1.4.0-rc.0
[`v1.4.0`]: https://github.com/sigp/lighthouse/releases/tag/v1.4.0

From time-to-time, Lighthouse *release candidates* will be published on the [sigp/lighthouse]
repository. Release candidates are previously known as Pre-Releases. These releases have passed the usual automated testing, however the developers would
like to see it running "in the wild" in a variety of configurations before declaring it an official,
stable release. Release candidates are also used by developers to get feedback from users regarding the
ergonomics of new features or changes.

Github will clearly show such releases as a "Pre-release" and they *will not* show up on
[sigp/lighthouse/releases/latest]. However, release candidates *will* show up on the
[sigp/lighthouse/releases] page, so **please pay attention to avoid the release candidates when
you're looking for stable Lighthouse**.

From time to time, Lighthouse may use the terms "release candidate" and "pre release"
interchangeably. A pre release is identical to a release candidate.

### Examples

[`v1.4.0-rc.0`] has `rc` in the version string and is therefore a release candidate. This release is
*not* stable and is *not* intended for critical tasks on mainnet (e.g., staking).

However, [`v1.4.0`] is considered stable since it is not marked as a release candidate and does not
contain `rc` in the version string. This release is intended for use on mainnet.

## When to use a release candidate

Users may wish to try a release candidate for the following reasons:

- To preview new features before they are officially released.
- To help detect bugs and regressions before they reach production.
- To provide feedback on annoyances before they make it into a release and become harder to change or revert.

There can also be a scenario that a bug has been found and requires an urgent fix. An example of incidence is [v4.0.2-rc.0](https://github.com/sigp/lighthouse/releases/tag/v4.0.2-rc.0) which contains a hot-fix to address high CPU usage experienced after the [Capella](https://ethereum.org/en/history/#capella) upgrade on 12<sup>th</sup> April 2023.  In this scenario, we will announce the release candidate on [Github](https://github.com/sigp/lighthouse/releases) and also on [Discord](https://discord.gg/cyAszAh) to recommend users to update to the release candidate version. 

## When *not* to use a release candidate

Other than the above scenarios, it is generally not recommended to use release candidates for any critical tasks on mainnet (e.g., staking). To test new release candidate features, try one of the testnets (e.g., Goerli).

