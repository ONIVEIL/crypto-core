# Contributing

Reviews, questions and pull requests are welcome — you do not need to be a cryptographer to point out something that looks wrong.

- **Design or code concerns:** open a public issue. `AUDIT_QUESTIONS.md` lists what the author would most like a second opinion on.
- **Something that looks exploitable:** please report privately, see `SECURITY.md`.
- **Pull requests:** small, focused changes are easiest to review (a fix, a missing test, a clearer comment). Run `npm ci && npm test && npm run typecheck` first. A failing test that demonstrates a problem is as valuable as a fix.
- **Scope:** this repository is only the crypto core. Changes to transport, UI or the rest of the app cannot be applied here, but feedback on how the core is used is still useful.
- **Language:** comments and docs are in English; some runtime strings are still German and can be translated in a PR.

Be kind to each other; this is an early-stage project and all feedback is appreciated.
