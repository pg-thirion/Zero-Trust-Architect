# Zero Trust Architect

A defensive cybersecurity strategy game for the browser. Design a fictional company network, allocate a limited budget and assess the design against simulated threats.

## Play locally

Clone this repository and serve its root with a static server:

```sh
python -m http.server 8000
```

Visit http://localhost:8000. No build step, dependencies, credentials, API keys or backend are required.

## Missions

| Company | Scenario | Fictional budget |
| --- | --- | --- |
| Northstar Studio | Small business | $128k |
| Meridian Health | Healthcare | $175k |
| Atlas Commerce | Enterprise | $205k |

Choose from 14 security controls across identity, endpoints, network, data protection and monitoring. Configure six routes between six network zones. Verified access costs $4k per route and requires microsegmentation to be enforced. Denying a required route damages business availability.

The eight fictional incident types cover compromised credentials, privileged account abuse, compromised suppliers, ransomware, application flaws, exfiltration, stolen storage and backup tampering.

The score is 75% security and 25% business availability. Threat loss is weighted by impact: prevented = 0%, contained = 35%, recovered = 65%, compromised = 100%. Results are deterministic. Per-mission designs and best scores are stored locally in the browser. Reports can be exported as plain text.

## Tests

```sh
node tests.js
```

The regression suite covers budgets, input sanitisation, threat outcomes, route enforcement, control dependencies and state immutability. It also runs seeded invariant checks against 1,500 generated designs.

To run the real-browser checks, install Google Chrome and the pinned development-only test tool:

```sh
npm install --no-save --no-package-lock --ignore-scripts playwright-core@1.56.1
node browser-tests.cjs
```

The browser suite checks desktop and mobile layouts, gameplay, report downloads, persistence, malformed saved data, reset and console errors.

## Deploy

For GitHub Pages, open **Settings > Pages > Build and deployment > Source** and select **GitHub Actions**. The `Test and publish to GitHub Pages` workflow runs syntax checks, simulation tests and real-browser tests before publishing the five runtime files. It can also be triggered manually from the Actions tab. No secrets or environment variables are needed.

The expected public URL is https://pg-thirion.github.io/Zero-Trust-Architect/. The site can also be hosted on any static hosting platform.

## Limitations

This is a simplified educational simulation, not a real security assessment or a claim of compliance with a security framework. It does not scan, attack or connect to real networks. Game costs and threat weights are fictional. Browser storage is local and is not synced across devices.
