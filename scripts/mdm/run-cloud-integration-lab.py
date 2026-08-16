#!/usr/bin/env python3
"""Build and run the stateful multi-device HOL Guard MDM Cloud Docker lab."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import uuid
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[2]
COMPOSE_FILE = ROOT / "scripts" / "mdm" / "cloud-lab" / "docker-compose.yml"
REPORT_SCHEMA = ROOT / "docs" / "guard" / "schemas" / "mdm-cloud-lab-report-v1.schema.json"
DEFAULT_ARTIFACTS = ROOT / "artifacts" / "mdm-cloud-lab"
SERVICES = ("cloud", "proxy", "device-a", "device-b", "device-c", "device-d")


def _run(
    command: list[str],
    *,
    env: dict[str, str],
    capture: bool = False,
    check: bool = False,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=ROOT,
        env=env,
        check=check,
        text=True,
        capture_output=capture,
    )


def _export_volume_file(
    base: list[str],
    source: str,
    destination: Path,
    *,
    env: dict[str, str],
) -> bool:
    result = _run(
        [
            *base,
            "run",
            "--rm",
            "--no-deps",
            "--entrypoint",
            "/bin/cat",
            "orchestrator",
            source,
        ],
        env=env,
        capture=True,
    )
    if result.returncode != 0 or not result.stdout.strip():
        return False
    destination.write_text(result.stdout, encoding="utf-8")
    return True


def _validate_report(report_path: Path) -> dict[str, object]:
    report = json.loads(report_path.read_text(encoding="utf-8"))
    schema = json.loads(REPORT_SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(report)
    if report.get("healthy") is not True:
        raise RuntimeError("MDM Cloud lab report is unhealthy")
    steps = report.get("steps")
    if not isinstance(steps, list) or len(steps) < 50:
        raise RuntimeError("MDM Cloud lab report did not cover the full matrix")
    if any(not isinstance(step, dict) or step.get("passed") is not True for step in steps):
        raise RuntimeError("MDM Cloud lab report contains a failed assertion")
    native = report.get("nativeCertification")
    if not isinstance(native, dict) or native.get("outcome") != "not-evaluated":
        raise RuntimeError("MDM Cloud lab overstated native certification")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keep", action="store_true", help="preserve containers and state after the run")
    parser.add_argument("--no-build", action="store_true", help="use an already-built lab image")
    parser.add_argument("--project", default=f"hol-guard-mdm-cloud-lab-{uuid.uuid4().hex[:8]}")
    parser.add_argument("--artifacts", type=Path, default=DEFAULT_ARTIFACTS)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    artifacts = args.artifacts.resolve()
    artifacts.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env.update(
        {
            "HOL_MDM_LAB_PROJECT": args.project,
            "COMPOSE_PROGRESS": env.get("COMPOSE_PROGRESS", "plain"),
        }
    )
    base = [
        "docker",
        "compose",
        "--project-name",
        args.project,
        "--file",
        str(COMPOSE_FILE),
    ]
    up = [*base, "up", "-d"]
    if not args.no_build:
        up.append("--build")
    up.extend(["--wait", "--wait-timeout", "180", *SERVICES])
    initial = [
        *base,
        "run",
        "--rm",
        "--no-deps",
        "orchestrator",
        "scripts/mdm/cloud-lab/orchestrator.py",
        "--json",
        "--phase",
        "initial",
        "--output",
        "/artifacts/mdm-cloud-integration-initial.json",
    ]
    restart = [*base, "restart", *SERVICES]
    wait_after_restart = [
        *base,
        "up",
        "-d",
        "--wait",
        "--wait-timeout",
        "180",
        *SERVICES,
    ]
    resume = [
        *base,
        "run",
        "--rm",
        "--no-deps",
        "orchestrator",
        "scripts/mdm/cloud-lab/orchestrator.py",
        "--json",
        "--phase",
        "restart",
        "--input-report",
        "/artifacts/mdm-cloud-integration-initial.json",
        "--output",
        "/artifacts/mdm-cloud-integration-report.json",
    ]
    down = [*base, "down", "--volumes", "--remove-orphans"]
    if args.dry_run:
        print(
            json.dumps(
                {
                    "up": up,
                    "initial": initial,
                    "restart": restart,
                    "waitAfterRestart": wait_after_restart,
                    "resume": resume,
                    "down": down,
                    "artifacts": str(artifacts),
                },
                sort_keys=True,
            )
        )
        return 0

    report_path = artifacts / "mdm-cloud-integration-report.json"
    initial_path = artifacts / "mdm-cloud-integration-initial.json"
    logs_path = artifacts / "compose.log"
    ps_path = artifacts / "compose-ps.json"
    status = 1
    try:
        if _run(up, env=env).returncode != 0:
            return 1
        initial_result = _run(initial, env=env)
        _export_volume_file(
            base,
            "/artifacts/mdm-cloud-integration-initial.json",
            initial_path,
            env=env,
        )
        if initial_result.returncode != 0:
            return initial_result.returncode
        if _run(restart, env=env).returncode != 0:
            return 1
        if _run(wait_after_restart, env=env).returncode != 0:
            return 1
        resume_result = _run(resume, env=env)
        if not _export_volume_file(
            base,
            "/artifacts/mdm-cloud-integration-report.json",
            report_path,
            env=env,
        ):
            print("MDM Cloud lab did not produce its bounded report artifact", file=sys.stderr)
            return resume_result.returncode or 1
        if resume_result.returncode != 0:
            return resume_result.returncode
        report = _validate_report(report_path)
        digest = hashlib.sha256(report_path.read_bytes()).hexdigest()
        (artifacts / "mdm-cloud-integration-report.json.sha256").write_text(
            f"{digest}  {report_path.name}\n",
            encoding="utf-8",
        )
        print(json.dumps(report, indent=2, sort_keys=True))
        status = 0
        return 0
    except (OSError, json.JSONDecodeError, RuntimeError) as error:
        print(f"MDM Cloud lab failed: {error}", file=sys.stderr)
        return 1
    finally:
        logs = _run([*base, "logs", "--no-color", "--tail", "1000"], env=env, capture=True)
        logs_path.write_text((logs.stdout or "") + (logs.stderr or ""), encoding="utf-8")
        ps = _run([*base, "ps", "--all", "--format", "json"], env=env, capture=True)
        ps_path.write_text(ps.stdout or "[]\n", encoding="utf-8")
        if not args.keep:
            _run(down, env=env)
        if status != 0:
            print(f"MDM Cloud lab logs: {logs_path}", file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
