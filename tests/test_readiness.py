"""
Readiness and startup-gating tests for the main API surface.

Run: pytest tests/test_readiness.py -v
"""

import os
import sys

from fastapi.testclient import TestClient

# Ensure startup avoids waiting on Ollama during tests.
os.environ.setdefault("SKIP_OLLAMA_WAIT", "true")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

import main  # noqa: E402


def test_api_info_includes_readiness_contract():
    with TestClient(main.app) as client:
        main._set_readiness(  # type: ignore[attr-defined]
            "ready_for_verify",
            verify_enabled=True,
            checks={
                "certificate_store": "ready",
                "oracle_target": "ready",
                "ollama": "ready",
                "model": "ready",
                "on_chain": "ready",
                "hardware_attestation": "ready",
            },
            blocking_issues=[],
            warnings=[],
        )
        response = client.get("/api/info")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ready_for_verify"
    assert body["verify_enabled"] is True
    assert body["readiness"]["checks"]["ollama"] == "ready"
    assert body["readiness"]["checks"]["on_chain"] == "ready"
    assert body["readiness"]["checks"]["hardware_attestation"] == "ready"


def test_health_returns_503_when_verify_is_not_ready():
    with TestClient(main.app) as client:
        main._set_readiness(  # type: ignore[attr-defined]
            "degraded",
            verify_enabled=False,
            checks={
                "certificate_store": "ready",
                "oracle_target": "ready",
                "ollama": "error",
                "model": "error",
                "on_chain": "missing_config",
                "hardware_attestation": "simulated",
            },
            blocking_issues=["Ollama/model startup failed: timeout"],
            warnings=[],
        )
        response = client.get("/health")

    assert response.status_code == 503
    body = response.json()
    assert body["status"] == "degraded"
    assert body["readiness"]["verify_enabled"] is False


def test_verify_returns_503_when_pipeline_not_ready():
    with TestClient(main.app) as client:
        main._set_readiness(  # type: ignore[attr-defined]
            "warming_up",
            verify_enabled=False,
            checks={
                "certificate_store": "ready",
                "oracle_target": "ready",
                "ollama": "pending",
                "model": "pending",
                "on_chain": "ready",
                "hardware_attestation": "ready",
            },
            blocking_issues=["Verification pipeline still warming up."],
            warnings=[],
        )
        response = client.post(
            "/api/verify",
            json={
                "credentials": {"license_number": "209311"},
                "disclosed_fields": ["specialty"],
            },
        )

    assert response.status_code == 503
    body = response.json()
    assert body["detail"]["error"] == "Verification pipeline not ready"
    assert body["detail"]["readiness"]["status"] == "warming_up"


def test_evaluate_onchain_readiness_requires_config_without_local_dev_flags(monkeypatch):
    for env_name in ("SKIP_TLS_VERIFY", "SKIP_ENCRYPTION", "SKIP_OLLAMA_WAIT", "SKIP_MODEL_PIN"):
        monkeypatch.delenv(env_name, raising=False)
    monkeypatch.delenv("CONTRACT_ADDRESS", raising=False)
    monkeypatch.delenv("PRIVATE_KEY", raising=False)

    status, blocker, warning = main._evaluate_onchain_readiness()  # type: ignore[attr-defined]

    assert status == "missing_config"
    assert blocker == (
        "On-chain storage is required for ready_for_verify but "
        "CONTRACT_ADDRESS and PRIVATE_KEY are not set."
    )
    assert warning is None


def test_evaluate_onchain_readiness_skips_enforcement_in_local_dev(monkeypatch):
    monkeypatch.setenv("SKIP_TLS_VERIFY", "true")
    monkeypatch.delenv("CONTRACT_ADDRESS", raising=False)
    monkeypatch.delenv("PRIVATE_KEY", raising=False)

    status, blocker, warning = main._evaluate_onchain_readiness()  # type: ignore[attr-defined]

    assert status == "skipped_local_dev"
    assert blocker is None
    assert warning == "On-chain readiness is not enforced because local-dev bypass flags are enabled."


def test_evaluate_hardware_readiness_requires_real_dstack(monkeypatch):
    for env_name in ("SKIP_TLS_VERIFY", "SKIP_ENCRYPTION", "SKIP_OLLAMA_WAIT", "SKIP_MODEL_PIN"):
        monkeypatch.delenv(env_name, raising=False)
    monkeypatch.setattr(main, "get_dstack_client", lambda: None)

    status, blocker, warning = main._evaluate_hardware_readiness()  # type: ignore[attr-defined]

    assert status == "simulated"
    assert blocker == (
        "Hardware-backed trust requires a real dstack/TDX environment, "
        "but no dstack client is available."
    )
    assert warning is None


def test_evaluate_hardware_readiness_skips_enforcement_in_local_dev(monkeypatch):
    monkeypatch.setenv("SKIP_ENCRYPTION", "true")

    status, blocker, warning = main._evaluate_hardware_readiness()  # type: ignore[attr-defined]

    assert status == "skipped_local_dev"
    assert blocker is None
    assert warning == (
        "Hardware attestation readiness is not enforced because local-dev bypass flags are enabled."
    )
