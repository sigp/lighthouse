# Update Priorities

When publishing releases, Lighthouse will include an "Update Priority" section in the release notes. As an example, see the [release notes from v2.1.2](https://github.com/sigp/lighthouse/releases/tag/v2.1.2)).

The "Update Priority" section will include a table which may appear like so:

| User Class        | Beacon Node     | Validator Client |
|-------------------|-----------------|------------------|
| Staking Users     | Medium Priority | Low Priority     |
| Non-Staking Users | Low Priority    | ---              |

To understand this table, the following terms are important:

- *Staking users* are those who use `lighthouse bn` and `lighthouse vc` to stake on the Beacon Chain.
- *Non-staking users* are those who run a `lighthouse bn` for non-staking purposes (e.g., data analysis or applications).
- *High priority* updates should be completed as soon as possible (e.g., hours or days).
- *Medium priority* updates should be completed at the next convenience (e.g., days or a week).
- *Low priority* updates should be completed in the next routine update cycle (e.g., two weeks).

Therefore, in the table above, staking users should update their BN in the next days or week and
their VC in the next routine update cycle. Non-staking should also update their BN in the next
routine update cycle.
