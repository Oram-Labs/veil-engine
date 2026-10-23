# Security policy

## Reporting a vulnerability

Please don't open a public issue. Report it privately through GitHub: on this repository's **Security** tab, choose **Report a vulnerability**, or go to <https://github.com/Oram-Labs/veil-engine/security/advisories/new>.

Useful to include:

- what an attacker can do, and what they need first;
- the smallest input or code that shows it;
- the version or commit you tested.

We aim to reply within a week, and will tell you when a fix is released. If you'd like credit in the advisory, say how you'd like to be named.

## What counts

Anything that breaks a promise in the [README](crates/engine/README.md#guarantees) or the [threat model](THREAT_MODEL.md). For example:

- a value the engine detects reaching its output unredacted;
- a placeholder restoring to the wrong value, or to a value from another scope;
- a report, match, statistic or error showing a value;
- the vault exposing values without its key, or opening with the wrong key.

A value that no detector recognises is a detection gap rather than a vulnerability. Please open an ordinary issue for it, with a made-up example.

## Supported versions

Fixes go into the latest release.
