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

The regression suite covers budgets, input sanitisation, threat outcomes, route enforcement, control dependencies and state immutability.

## Deploy

Use GitHub Pages with main and the repository root as the publishing source, or any static hosting platform. No secrets or environment variables are needed.

## Limitations

This is a simplified educational simulation, not a real security assessment or a claim of compliance with a security framework. It does not scan, attack or connect to real networks. Game costs and threat weights are fictional. Browser storage is local and is not synced across devices.
