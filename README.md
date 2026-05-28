# Agent Incident Relay MCP

> ## 🧱 Part of the MEOK A2A Substrate (£999/mo) + Governance Substrate (£499/mo)
> See [meok.ai/a2a](https://meok.ai/a2a).

# Article 73 5-clock broadcaster — one incident, five signed regulatory reports

<!-- mcp-name: io.github.CSOAI-ORG/agent-incident-relay-mcp -->

[![PyPI](https://img.shields.io/pypi/v/agent-incident-relay-mcp)](https://pypi.org/project/agent-incident-relay-mcp/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

## What this does

EU regulated AI systems live under **five concurrent regulatory regimes**. When an incident happens, missing one clock = enforcement action.

This MCP takes ONE incident description, classifies which regimes apply, and starts ALL the clocks simultaneously. It emits per-regime signed payloads ready for submission to each national authority.

| # | Regime | Earliest clock | Authority |
|---|---|---|---|
| 1 | **EU AI Act Article 73** | 15 days to deployer | National AI competent authority + AI Office |
| 2 | **DORA Article 19** | 4 hours initial | National financial supervisor + ESAs |
| 3 | **NIS2 Article 23** | 24 hours early warning | National CSIRT + competent authority |
| 4 | **GDPR Article 33** | 72 hours | National DPA |
| 5 | **ISO/IEC 42001 cl 10.1** | 24h internal | Internal AIMS + external auditor |

## Tools

| Tool | Purpose |
|---|---|
| `classify_incident(description, severity?)` | Which regimes apply? Auto-detect severity. |
| `relay_incident(description, regimes?, severity, entity_id)` | Start all clocks from one detection timestamp |
| `check_clock_status(incident_id)` | How many hours remain on each clock? |
| `generate_authority_payload(incident_id, regime, extra_fields?)` | Regime-formatted submission payload |
| `sign_relay(incident_id)` | HMAC-seal the full 5-regime relay for audit |
| `list_regimes()` | Full regime spec — clocks, authorities, schemas |

## Why this matters

Today GRC teams maintain five separate spreadsheets and miss deadlines because the clocks all start at different events. This MCP gives you one incident_id that drives all five regimes from the same detection timestamp, with cryptographic non-repudiation.

Companion to:
- `ai-incident-reporting-mcp` (classifier-only, no broadcast)
- `dora-nis2-crosswalk-mcp` (regulation-to-regulation map)
- `agent-audit-logger-mcp` (the chain-of-custody log for the submitted payloads)

## Sister MCPs

Part of the MEOK **A2A** + **Governance** packs:

- `bft-progress-council-mcp` — anti-loop for the response team
- `agent-audit-logger-mcp` — HMAC-chained log of every submission
- `agent-policy-enforcement-mcp` — gate on incident-response approval
- `eu-ai-act-compliance-mcp` — Article 73 text + thresholds

Full catalogue: [meok.ai/anthropic-registry](https://meok.ai/anthropic-registry)

## Pricing

| Option | Price |
|---|---|
| Self-host MIT | £0 |
| Universal PAYG | £29/mo + £0.0002/call |
| Governance Substrate | £499/mo |
| A2A Substrate | £999/mo |
| Defence | £4,990/mo |

Buy: https://meok.ai/a2a

## Licence

MIT. By [MEOK AI Labs](https://meok.ai) (CSOAI LTD, UK Companies House 16939677).

<!-- BUY-LADDER:START -->

## 💸 Try MEOK in 30 seconds — instant buy ladder

| Tier | Price | What you get | Stripe |
|---|---|---|---|
| Smoke test | **£1** | Signed sample MCP-Hardening report + Article 50 PDF | <https://buy.stripe.com/dRmcN75ScdQS7oh1Uc8k90U> |
| Quick Kit | **£9** | EU AI Act Article 50 implementation guide (C2PA + EU-Icon) | <https://buy.stripe.com/cNi00la8s1460ZT0Q88k90V> |
| Founder Call | **£29** | 30-min 1-on-1 with the founder | <https://buy.stripe.com/8x228ta8s6oqbExaqI8k90W> |

> Refundable. UK Stripe — VAT-clean. Builds on the 81-MCP MEOK fleet.
> Verify any signed report at <https://meok.ai/verify>.

<!-- BUY-LADDER:END -->

