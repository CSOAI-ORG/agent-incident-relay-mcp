#!/usr/bin/env python3
"""
Agent Incident Relay MCP — Article 73 5-clock broadcaster
=========================================================

By MEOK AI Labs · https://meok.ai · MIT
<!-- mcp-name: io.github.CSOAI-ORG/agent-incident-relay-mcp -->

WHAT THIS DOES
--------------
One incident triggers FIVE concurrent regulatory clocks in EU regulated AI:

  1. EU AI Act Article 73       — 15 days to provider, then 72h to notified body
  2. DORA Article 19             — 4h initial, 72h intermediate, 1 month final
  3. NIS2 Article 23             — 24h early warning, 72h incident report, 1 month final
  4. GDPR Article 33             — 72h to supervisory authority
  5. ISO/IEC 42001 clause 10.1  — internal nonconformity record (no external clock)

This MCP takes one incident description and emits five signed reports — one per
regime — formatted for each authority's expected payload. Every report is
HMAC-SHA256 signed for non-repudiation, and the relay returns a single
incident_id that auditors can use to verify the full chain.

WHY THIS MATTERS
----------------
EU regulated AI systems (banks, insurers, healthcare, energy, telco) live under
ALL FIVE of these regimes simultaneously. When an incident happens, missing one
clock = enforcement action. Today, GRC teams maintain five spreadsheets and miss
deadlines. This MCP fixes that.

TOOLS
-----
- classify_incident(description): which regimes apply? severity?
- relay_incident(incident, regimes): broadcast one incident to N regimes
- check_clock_status(incident_id): how many hours remain on each clock?
- generate_authority_payload(incident, regime): payload formatted per regime
- sign_relay(incident_id): HMAC-sign the full 5-regime relay

PRICING
-------
Free MIT self-host · £29/mo Starter · £79/mo Pro · A2A Substrate £999/mo.
"""

from __future__ import annotations
import hashlib
import hmac
import json
import os
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional
from mcp.server.fastmcp import FastMCP


mcp = FastMCP("agent-incident-relay")
_HMAC_SECRET = os.environ.get("MEOK_HMAC_SECRET", "")
_INCIDENTS: dict[str, dict] = {}


# ──────────────────────────────────────────────────────────────────────
# Regime clock specs (hours from incident detection)
# ──────────────────────────────────────────────────────────────────────
REGIMES = {
    "EU_AI_ACT_ART_73": {
        "name": "EU AI Act Article 73",
        "applies_to": "Providers of high-risk AI systems (Annex III)",
        "clocks": [
            {"label": "Notify deployer", "hours": 360},                      # 15 days
            {"label": "Notify market-surveillance authority", "hours": 360},  # 15 days
            {"label": "Submit full incident report (notified body)", "hours": 432},  # 18 days
        ],
        "authority": "National AI competent authority + AI Office",
        "payload_schema": ["provider_id", "system_id", "severity", "fundamental_rights_impact",
                           "deaths_or_serious_injury", "interruption_critical_service",
                           "property_damage", "discrimination_evidence"],
    },
    "DORA_ART_19": {
        "name": "DORA Article 19",
        "applies_to": "Financial entities (banks, insurers, CASPs, CTPPs)",
        "clocks": [
            {"label": "Initial notification to competent authority", "hours": 4},
            {"label": "Intermediate report", "hours": 72},
            {"label": "Final report", "hours": 720},  # 1 month
        ],
        "authority": "National financial supervisor (BaFin/PRA/AMF/etc.) + ESAs",
        "payload_schema": ["entity_id", "lei", "classification_major", "root_cause",
                           "affected_services", "financial_impact_eur",
                           "clients_affected", "third_party_involved"],
    },
    "NIS2_ART_23": {
        "name": "NIS2 Article 23",
        "applies_to": "Essential + important entities (sec 30/32 of NIS2 de)",
        "clocks": [
            {"label": "Early warning to CSIRT/CA", "hours": 24},
            {"label": "Incident notification", "hours": 72},
            {"label": "Final report", "hours": 720},  # 1 month
        ],
        "authority": "National CSIRT + competent authority (BSI/ANSSI/NCSC)",
        "payload_schema": ["entity_id", "sector_annex_i_or_ii", "significant_incident",
                           "cross_border", "ms_affected", "indicators_of_compromise",
                           "mitigation_actions"],
    },
    "GDPR_ART_33": {
        "name": "GDPR Article 33",
        "applies_to": "Controllers in case of personal data breach",
        "clocks": [
            {"label": "Notify supervisory authority", "hours": 72},
        ],
        "authority": "National DPA (ICO/CNIL/BfDI/etc.)",
        "payload_schema": ["controller_id", "nature_of_breach", "categories_of_data",
                           "approximate_data_subjects", "likely_consequences",
                           "measures_taken_or_proposed", "dpo_contact"],
    },
    "ISO_42001_CL_10_1": {
        "name": "ISO/IEC 42001 clause 10.1 (nonconformity)",
        "applies_to": "Any org operating ISO 42001-certified AIMS",
        "clocks": [
            {"label": "Internal nonconformity record", "hours": 24},
            {"label": "Root-cause analysis + corrective action plan", "hours": 720},
        ],
        "authority": "Internal AIMS + external auditor at next surveillance visit",
        "payload_schema": ["nonconformity_id", "annex_a_control_affected",
                           "root_cause", "corrective_action", "responsible_owner"],
    },
}


def _sign(payload: dict) -> str:
    if not _HMAC_SECRET:
        return "unsigned-no-key-configured"
    return hmac.new(_HMAC_SECRET.encode(), json.dumps(payload, sort_keys=True).encode(), hashlib.sha256).hexdigest()


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


# ──────────────────────────────────────────────────────────────────────
# Tools
# ──────────────────────────────────────────────────────────────────────

@mcp.tool()
def classify_incident(description: str, severity: Optional[str] = None) -> dict:
    """
    Determine which of the 5 regulatory regimes apply to this incident.

    Args:
        description: Free-text incident description.
        severity: Optional explicit severity ("minor", "major", "critical").

    Returns:
        {applicable_regimes, severity, recommendation}
    """
    d = description.lower()
    applies = []
    # Heuristic mapping — production tightens with a classifier
    if any(k in d for k in ["ai system", "ml model", "llm", "agent",
                            "high-risk", "annex iii", "annex i", "fundamental rights",
                            "discrimination", "bias output"]):
        applies.append("EU_AI_ACT_ART_73")
    if any(k in d for k in ["financial", "bank", "insurer", "casp", "fintech",
                            "trading", "payment", "operational resilience",
                            "ict", "third-party provider"]):
        applies.append("DORA_ART_19")
    if any(k in d for k in ["cyber", "ransomware", "ddos", "intrusion", "outage",
                            "essential entity", "important entity", "network and information"]):
        applies.append("NIS2_ART_23")
    if any(k in d for k in ["personal data", "pii", "breach", "leak", "unauthorised access",
                            "data subject", "gdpr"]):
        applies.append("GDPR_ART_33")
    if any(k in d for k in ["nonconformity", "iso 42001", "aims", "annex a control"]):
        applies.append("ISO_42001_CL_10_1")

    # Default to ISO 42001 if anything AI-related
    if applies and "ISO_42001_CL_10_1" not in applies and any("AI" in r for r in applies):
        applies.append("ISO_42001_CL_10_1")

    # Severity heuristic
    sev = severity
    if not sev:
        if any(k in d for k in ["death", "serious injury", "critical", "fatal",
                                "ransomware", "data leak >100k", "discrimination"]):
            sev = "critical"
        elif any(k in d for k in ["major", "outage", "breach", "unauthorised"]):
            sev = "major"
        else:
            sev = "minor"

    return {
        "applicable_regimes": applies,
        "severity": sev,
        "recommendation": "Call relay_incident() with this regime list to start all clocks at the same incident timestamp.",
        "regimes_count": len(applies),
    }


@mcp.tool()
def relay_incident(
    description: str,
    detected_at: Optional[str] = None,
    regimes: Optional[list[str]] = None,
    severity: str = "major",
    entity_id: str = "unspecified",
) -> dict:
    """
    Broadcast one incident to ALL applicable regulatory regimes simultaneously.

    Args:
        description: Free-text incident description.
        detected_at: ISO timestamp of detection. Defaults to now.
        regimes: List of regime keys (from REGIMES). If None, auto-classify.
        severity: "minor" | "major" | "critical".
        entity_id: Your regulated entity identifier (LEI, MS reg no, etc.).

    Returns:
        {incident_id, started_at, regime_clocks: [...], next_actions: [...]}
    """
    if regimes is None:
        classification = classify_incident(description, severity)
        regimes = classification["applicable_regimes"]

    incident_id = f"INC_{int(time.time())}_{uuid.uuid4().hex[:8]}"
    detected = detected_at or _ts()
    detected_dt = datetime.fromisoformat(detected.replace("Z", "+00:00"))

    clocks = []
    for reg_key in regimes:
        if reg_key not in REGIMES:
            continue
        reg = REGIMES[reg_key]
        for clk in reg["clocks"]:
            deadline = detected_dt + timedelta(hours=clk["hours"])
            clocks.append({
                "regime": reg_key,
                "regime_name": reg["name"],
                "clock_label": clk["label"],
                "hours_from_detection": clk["hours"],
                "deadline_iso": deadline.isoformat(),
                "status": "open",
                "authority": reg["authority"],
            })

    incident = {
        "incident_id": incident_id,
        "description": description,
        "detected_at": detected,
        "severity": severity,
        "entity_id": entity_id,
        "regimes": regimes,
        "clocks": clocks,
        "created_at": _ts(),
        "status": "active",
    }
    _INCIDENTS[incident_id] = incident

    return {
        "incident_id": incident_id,
        "started_at": detected,
        "regime_clocks": clocks,
        "next_actions": [
            f"Call generate_authority_payload(incident_id='{incident_id}', regime='<KEY>') for each regime",
            f"Call sign_relay(incident_id='{incident_id}') when all payloads are submitted",
            f"Use check_clock_status(incident_id='{incident_id}') to monitor remaining time",
        ],
        "earliest_deadline": min((c["deadline_iso"] for c in clocks), default=None),
    }


@mcp.tool()
def check_clock_status(incident_id: str) -> dict:
    """
    How many hours remain on each clock for this incident?

    Args:
        incident_id: From relay_incident().

    Returns:
        {incident_id, clocks_with_remaining_hours, missed_clocks, ...}
    """
    if incident_id not in _INCIDENTS:
        return {"error": f"Unknown incident_id: {incident_id}"}
    inc = _INCIDENTS[incident_id]
    now = datetime.now(timezone.utc)
    out = []
    missed = []
    for c in inc["clocks"]:
        deadline = datetime.fromisoformat(c["deadline_iso"].replace("Z", "+00:00"))
        remaining_h = (deadline - now).total_seconds() / 3600
        rec = {**c, "hours_remaining": round(remaining_h, 2)}
        out.append(rec)
        if remaining_h < 0 and c["status"] == "open":
            missed.append(rec)
    return {
        "incident_id": incident_id,
        "now": _ts(),
        "clocks": out,
        "missed_clocks": missed,
        "all_clear": len(missed) == 0,
    }


@mcp.tool()
def generate_authority_payload(incident_id: str, regime: str, extra_fields: Optional[dict] = None) -> dict:
    """
    Render the per-regime payload formatted for that authority's submission endpoint.

    Args:
        incident_id: From relay_incident().
        regime: One of EU_AI_ACT_ART_73 / DORA_ART_19 / NIS2_ART_23 / GDPR_ART_33 / ISO_42001_CL_10_1.
        extra_fields: Optional dict of regime-specific fields to merge.

    Returns:
        {payload, schema, authority, submission_hint}
    """
    if incident_id not in _INCIDENTS:
        return {"error": f"Unknown incident_id: {incident_id}"}
    if regime not in REGIMES:
        return {"error": f"Unknown regime: {regime}. Use one of {list(REGIMES.keys())}"}

    inc = _INCIDENTS[incident_id]
    reg = REGIMES[regime]
    payload = {
        "incident_id": incident_id,
        "regime": regime,
        "regime_name": reg["name"],
        "detected_at": inc["detected_at"],
        "severity": inc["severity"],
        "entity_id": inc["entity_id"],
        "description": inc["description"],
    }
    for field in reg["payload_schema"]:
        payload[field] = (extra_fields or {}).get(field, "<TO_FILL>")
    payload["signature"] = _sign(payload)
    return {
        "payload": payload,
        "schema": reg["payload_schema"],
        "authority": reg["authority"],
        "submission_hint": (
            "Submit to your national competent authority via the official portal "
            "(e.g. BaFin MVP, CSIRT.gov.de, ICO, CNIL e-notification, AI Office incident form)."
        ),
    }


@mcp.tool()
def sign_relay(incident_id: str) -> dict:
    """
    HMAC-sign the full multi-regime relay for non-repudiable audit evidence.

    Args:
        incident_id: From relay_incident().

    Returns:
        {signed, signature, sealed_at}
    """
    if incident_id not in _INCIDENTS:
        return {"error": f"Unknown incident_id: {incident_id}"}
    inc = _INCIDENTS[incident_id]
    sealed = {
        "incident_id": incident_id,
        "regimes": inc["regimes"],
        "clocks": inc["clocks"],
        "detected_at": inc["detected_at"],
        "entity_id": inc["entity_id"],
        "sealed_at": _ts(),
    }
    sig = _sign(sealed)
    inc["signature"] = sig
    inc["sealed_at"] = sealed["sealed_at"]
    inc["status"] = "sealed"
    return {
        "signed": _HMAC_SECRET != "",
        "signature": sig,
        "sealed_at": sealed["sealed_at"],
        "verify_hint": "Auditor can recompute signature with the same secret + sealed payload.",
    }


@mcp.tool()
def list_regimes() -> dict:
    """Return the full regime spec — clocks, authorities, payload schemas."""
    return {
        "regimes": REGIMES,
        "total_regimes": len(REGIMES),
        "total_clocks": sum(len(r["clocks"]) for r in REGIMES.values()),
    }


if __name__ == "__main__":
    mcp.run()
