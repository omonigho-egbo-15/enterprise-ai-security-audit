import sys
import os
import json
import pytest

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from scripts.simulate_telemetry import run_audit

PAYLOADS_PATH = os.path.join(BASE_DIR, "data", "nist_payloads.json")
REPORT_PATH = os.path.join(BASE_DIR, "reports", "telemetry_report.json")

@pytest.fixture(scope="session")
def telemetry_summary():
    assert os.path.exists(PAYLOADS_PATH), f"Missing payload dataset at {PAYLOADS_PATH}"
    report = run_audit(PAYLOADS_PATH, REPORT_PATH)
    return report["telemetry_summary"]

def test_nist_threat_blockage_threshold(telemetry_summary):
    rate = telemetry_summary["measured_blockage_rate"]
    target = telemetry_summary["target_blockage_threshold"]
    assert rate >= target

def test_zero_false_positive_sla_outages(telemetry_summary):
    fp_outages = telemetry_summary["false_positive_outage_incidents"]
    availability = telemetry_summary["sla_measured_availability"]
    target_sla = telemetry_summary["sla_target_availability"]
    assert fp_outages == 0
    assert availability >= target_sla

def test_ai_bom_alignment(telemetry_summary):
    ai_bom_path = os.path.join(BASE_DIR, "ai_bom.json")
    assert os.path.exists(ai_bom_path)
    with open(ai_bom_path, "r", encoding="utf-8") as f:
        ai_bom = json.load(f)
    tg = ai_bom["telemetryGates"]
    assert tg["minimumAdversarialBlockagePercent"] >= 85.0
    assert tg["currentMeasuredBlockagePercent"] >= 85.0
