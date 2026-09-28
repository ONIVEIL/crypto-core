# Security policy

This repository is an unaudited crypto core published for review. It is not production software and carries no security guarantees.

## Reporting a vulnerability

Please report anything that looks exploitable **privately**, not in a public issue:

- Use GitHub's private vulnerability reporting for this repository (Security tab → "Report a vulnerability").
- Alternative contact by e-mail: tsss19470@gmail.com

Please include the affected file/function, a description of the impact, and, if possible, a failing test or a minimal reproduction.

You can expect an acknowledgement, and the author will say whether they consider the report valid. There is no bug bounty.

## Design-level feedback

Concerns about the *design* (for example the weaker initial key agreement, see `THREAT_MODEL.md`) are exactly what this repository is for. Those can go into a normal public issue unless you believe they enable a practical attack.

## Scope

In scope: the code in this repository. Out of scope: the Tor/Orbot transport, group chat, UI and platform code, none of which are included here.
