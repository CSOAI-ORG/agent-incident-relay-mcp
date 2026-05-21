"""Smoke tests for agent-incident-relay-mcp."""
import sys, os, inspect, traceback
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from server import (
    classify_incident,
    relay_incident,
    check_clock_status,
    generate_authority_payload,
    sign_relay,
    list_regimes,
    REGIMES,
    _INCIDENTS,
)


def test_classify_ai_breach_picks_two_regimes():
    r = classify_incident("Our high-risk AI system leaked personal data of 50k users due to a bias output bug")
    assert "EU_AI_ACT_ART_73" in r["applicable_regimes"]
    assert "GDPR_ART_33" in r["applicable_regimes"]


def test_classify_financial_outage_picks_dora():
    r = classify_incident("Major ICT outage at our bank — trading platform down 4h")
    assert "DORA_ART_19" in r["applicable_regimes"]


def test_classify_severity_critical():
    r = classify_incident("Critical ransomware caused death and serious injury")
    assert r["severity"] == "critical"


def test_relay_creates_incident_with_clocks():
    _INCIDENTS.clear()
    r = relay_incident("AI bias incident", regimes=["EU_AI_ACT_ART_73", "GDPR_ART_33"], severity="major", entity_id="LEI-XYZ")
    assert r["incident_id"].startswith("INC_")
    assert len(r["regime_clocks"]) == 4  # 3 EU AI Act + 1 GDPR
    assert r["earliest_deadline"] is not None


def test_relay_auto_classifies_when_regimes_none():
    _INCIDENTS.clear()
    r = relay_incident("Personal data breach — leaked PII")
    # Should auto-classify and pick at least GDPR
    regimes_in_clocks = {c["regime"] for c in r["regime_clocks"]}
    assert "GDPR_ART_33" in regimes_in_clocks


def test_check_clock_status_returns_remaining():
    _INCIDENTS.clear()
    r = relay_incident("Outage", regimes=["DORA_ART_19"])
    inc_id = r["incident_id"]
    s = check_clock_status(inc_id)
    assert s["incident_id"] == inc_id
    assert len(s["clocks"]) == 3  # DORA has 3 clocks
    # DORA 4h initial is positive (just created)
    assert any(c["hours_remaining"] > 3 for c in s["clocks"])


def test_check_clock_status_unknown():
    r = check_clock_status("nope")
    assert "error" in r


def test_generate_payload_for_dora():
    _INCIDENTS.clear()
    r = relay_incident("ICT outage", regimes=["DORA_ART_19"], entity_id="LEI-ABC123")
    p = generate_authority_payload(r["incident_id"], "DORA_ART_19",
                                   {"lei": "LEI-ABC123", "classification_major": True})
    assert p["payload"]["regime"] == "DORA_ART_19"
    assert p["payload"]["lei"] == "LEI-ABC123"
    assert "signature" in p["payload"]


def test_generate_payload_unknown_regime():
    _INCIDENTS.clear()
    r = relay_incident("x", regimes=["DORA_ART_19"])
    p = generate_authority_payload(r["incident_id"], "FAKE_REGIME")
    assert "error" in p


def test_sign_relay_returns_signature():
    _INCIDENTS.clear()
    r = relay_incident("x", regimes=["GDPR_ART_33"])
    s = sign_relay(r["incident_id"])
    assert "signature" in s
    assert "sealed_at" in s


def test_list_regimes_has_5():
    r = list_regimes()
    assert r["total_regimes"] == 5
    assert "EU_AI_ACT_ART_73" in r["regimes"]
    assert "DORA_ART_19" in r["regimes"]
    assert "NIS2_ART_23" in r["regimes"]


if __name__ == "__main__":
    g = dict(globals())
    fns = [v for k, v in g.items() if k.startswith("test_") and inspect.isfunction(v)]
    p = f = 0
    for fn in fns:
        try:
            fn(); print(f"OK {fn.__name__}"); p += 1
        except Exception as e:
            print(f"X  {fn.__name__}: {type(e).__name__}: {e}"); traceback.print_exc(); f += 1
    print(f"\n{p} passed, {f} failed")
