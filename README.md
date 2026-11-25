# Zero Trust Architect

A dependency-free, defensive cybersecurity strategy game for the browser. Design a fictional company network, allocate a limited budget and evaluate the architecture against simulated incidents.

**Production:** https://zero-trust-architect.vercel.app/

## Play locally

Clone the repository and run `python -m http.server 8000` from the root. Visit http://localhost:8000. No build step, runtime dependencies, credentials, API keys or backend are required.

## Version 2

| Mission | Sector | Standard budget |
| --- | --- | --- |
| Northstar Studio | Small business | $128k |
| Meridian Health | Healthcare | $175k |
| Atlas Commerce | Enterprise | $205k |
| Harbour University | Education | $195k |
| Cobalt Finance | Financial services | $245k |
| Ironwood Manufacturing | Industrial enterprise | $225k |

There are 18 mission/difficulty combinations: Training (125% budget, 70-point target), Standard (100%, 75-point target) and Expert (80%, 80-point target). Every combination has independent saved designs, personal bests, history and checkpoints. The original v1 standard-mode saves are compatible.

### Gameplay and analysis

- 24 controls across five security domains, with six network zones and six configurable routes.
- 16 threat types, a full mission assessment and an individual threat laboratory.
- Four budget-aware strategy templates, bulk verification of required routes and denial of optional routes.
- Live projected score, projected security and availability, baseline comparison, investment efficiency and best single affordable upgrade.
- Five mission objectives, residual-risk register, control coverage by domain and route exposure summary.
- Catalogue search, category filter, installed/affordable filter, cost/name sorting and filter reset.
- Undo and redo (50 changes per session), including keyboard shortcuts.
- Saved checkpoint, comparison, restore and delete; portable JSON design export and validated import (64 KB limit).
- Last 20 assessments per mission/difficulty, five achievements based on retained history, history clearing with personal best preserved.
- Text assessment and CSV risk register downloads, expandable learning glossary.

The score is 75% security and 25% availability. Weighted loss: prevented = 0%, contained = 35%, recovered = 65%, compromised = 100%. Verified access costs $4k per route and requires microsegmentation; denying a critical route damages availability. The forecast and recommendation are based on the same deterministic model; the recommendation evaluates single upgrades, not a globally optimal architecture. Individual threat tests do not affect scores or history.

## Tests

```sh
node tests.js
npm install --no-save --no-package-lock --ignore-scripts playwright-core@1.56.1
node browser-tests.cjs
```

Chrome is required for browser tests. The test suite exercises original and expanded simulation logic, all difficulty/mission combinations, threat rules, import validation, deterministic scoring, budget invariants, UI interactions, exports, storage and desktop/mobile layouts (320, 390, 1024, 1440px). CI runs on main, pull requests and the v2 release branch. Vercel runs the engine suite before building and publishes only the five runtime files.

## Security and limitations

The site uses a restrictive content security policy and HTTP security headers. No runtime API calls are made. All data remains local to the user's browser unless they export a file. The simulation is an educational simplification, not a real network assessment or compliance certification. Costs, threat impact weights and companies are fictional. Undo/redo history is session-local; saved scores and designs are not synchronised across devices.
