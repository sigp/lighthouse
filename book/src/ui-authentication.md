# Authentication

## Siren Session

For enhanced security, Siren will require users to authenticate with their session password to access the dashboard. This is crucial because Siren now includes features that can permanently alter the status of the user's validators. The session password must be set during the [configuration](./ui-configuration.md) process before running the Docker or local build, either in an `.env` file or via Docker flags.

![exit](imgs/ui-session.png)

## Protected Actions

Prior to executing any sensitive validator action, Siren will request authentication of the session password. If you wish to update your password please refer to the Siren [configuration process](./ui-configuration.md).

![exit](imgs/ui-auth.png)
