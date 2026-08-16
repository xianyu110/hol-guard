from __future__ import annotations

import json

from orchestrator_support import (
    ALPHA,
    Recorder,
    _create_job,
    _device_fault,
    _job_status,
    _publish,
    _state,
    _sync,
)


def run_remediation_and_evidence(
    cloud: str,
    devices: dict[str, str],
    admin: str,
    recorder: Recorder,
    repair: dict[str, object],
) -> None:
    arbitrary = _create_job(
        cloud,
        admin,
        workspace=ALPHA,
        device="device-a",
        action="shell",
        parameters={"command": "curl attacker"},
        idempotency_key="idem-arbitrary-shell",
    )

    cross_tenant_job = _create_job(
        cloud,
        admin,
        workspace=ALPHA,
        device="device-d",
        action="repair",
        parameters={"scope": "machine"},
        idempotency_key="idem-cross-tenant",
    )

    recorder.add(
        "arbitrary commands and cross-tenant remediation are rejected",
        arbitrary.get("httpStatus") == 400
        and arbitrary.get("error") == "remediation_action_invalid"
        and cross_tenant_job.get("httpStatus") == 404,
        {"arbitrary": arbitrary, "crossTenant": cross_tenant_job},
    )

    executed = _sync(devices["device-a"])

    awaiting = _job_status(_state(cloud, admin, ALPHA), repair.get("jobId"))

    verified = _sync(devices["device-a"])

    verified_status = _job_status(_state(cloud, admin, ALPHA), repair.get("jobId"))

    recorder.add(
        "remediation is not complete until fresh healthy evidence arrives",
        executed.get("policyIntegrity") == "healthy"
        and awaiting == "awaiting_evidence"
        and verified.get("policyIntegrity") == "healthy"
        and verified_status == "succeeded",
        {"executed": executed, "awaiting": awaiting, "verifiedStatus": verified_status},
    )

    _device_fault(devices["device-a"], {"symlinkPolicy": True})

    symlinked = _sync(devices["device-a"])

    symlink_repair = _create_job(
        cloud,
        admin,
        workspace=ALPHA,
        device="device-a",
        action="repair",
        parameters={"scope": "machine"},
        idempotency_key="idem-repair-symlink",
    )

    _sync(devices["device-a"])

    _sync(devices["device-a"])

    recorder.add(
        "managed policy symlink substitution is tampered and repairable",
        symlinked.get("policyIntegrity") == "tampered"
        and symlinked.get("policyIntegrityReason") == "managed_policy_symlink"
        and _job_status(_state(cloud, admin, ALPHA), symlink_repair.get("jobId")) == "succeeded",
        {"symlinked": symlinked, "job": symlink_repair},
    )

    _device_fault(devices["device-a"], {"removePolicy": True})

    missing = _sync(devices["device-a"])

    missing_repair = _create_job(
        cloud,
        admin,
        workspace=ALPHA,
        device="device-a",
        action="repair",
        parameters={"scope": "machine"},
        idempotency_key="idem-repair-missing",
    )

    _sync(devices["device-a"])

    _sync(devices["device-a"])

    recorder.add(
        "missing managed policy remains unhealthy until repaired and re-attested",
        missing.get("policyIntegrity") == "missing"
        and _job_status(_state(cloud, admin, ALPHA), missing_repair.get("jobId")) == "succeeded",
        {"missing": missing, "job": missing_repair},
    )

    typed_actions = [
        ("integrity-scan", {}),
        ("policy-refresh", {}),
        ("service-register", {"service": "machine-health"}),
        ("service-register", {"service": "supervisor"}),
        ("version-converge", {"targetVersion": "3.0.0-test"}),
        ("install", {"targetVersion": "3.0.1-test"}),
    ]

    typed_results: dict[str, object] = {}

    for index, (action, parameters) in enumerate(typed_actions, start=1):
        key = f"idem-typed-{index}"
        job = _create_job(
            cloud,
            admin,
            workspace=ALPHA,
            device="device-a",
            action=action,
            parameters=parameters,
            idempotency_key=key,
        )
        _sync(devices["device-a"])
        _sync(devices["device-a"])
        typed_results[key] = {
            "action": action,
            "status": _job_status(_state(cloud, admin, ALPHA), job.get("jobId")),
        }

    recorder.add(
        "every fixed remediation action executes and is evidence-verified",
        all(
            isinstance(value, dict) and value.get("status") == "succeeded"
            for value in typed_results.values()
        ),
        typed_results,
    )

    final_state = _state(cloud, admin)

    serialized_state = json.dumps(final_state, sort_keys=True).lower()

    recorder.add(
        "audit evidence is hash-chained and redacts authority material",
        final_state.get("auditChainValid") is True
        and not any(
            material in serialized_state
            for material in (
                "enrollment-token-device-a",
                "curl attacker",
                "begin private key",
                "privatekeypem",
            )
        ),
        {
            "auditCount": len(final_state.get("audit", [])) if isinstance(final_state.get("audit"), list) else None,
            "auditChainValid": final_state.get("auditChainValid"),
        },
    )

    recorder.add(
        "all health sequences and acknowledgement identities are unique",
        len(
            {
                (item.get("workspace"), item.get("device"), item.get("sequence"))
                for item in final_state.get("health", [])
                if isinstance(item, dict)
            }
        )
        == len(final_state.get("health", []))
        and len(
            {
                item.get("request_id")
                for item in final_state.get("acks", [])
                if isinstance(item, dict)
            }
        )
        == len(final_state.get("acks", [])),
        {
            "healthCount": len(final_state.get("health", [])),
            "ackCount": len(final_state.get("acks", [])),
        },
    )

    _device_fault(devices["device-c"], {"holdOutbox": True})

    queued_publish = _publish(cloud, admin, ALPHA, ["device-c"], "observe")

    queued = _sync(devices["device-c"])

    recorder.add(
        "restart checkpoint leaves durable endpoint evidence queued",
        queued.get("outboxDepth", 0) > 0 and queued.get("revision") == queued_publish.get("revision"),
        queued,
    )
