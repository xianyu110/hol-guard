from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from codex_plugin_scanner.guard.native_runtime_admission import (
    NativeResidentAdmissionError,
    native_resident_admission,
    native_resident_admission_snapshot,
)
from codex_plugin_scanner.guard.native_runtime_resident import _ResidentService, resident_native_request


def test_native_admission_retries_one_transient_disconnect() -> None:
    calls = 0

    @native_resident_admission
    def request(*, operation: str) -> str:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise ConnectionResetError("synthetic local disconnect")
        return operation

    assert request(operation="command_model") == "command_model"
    assert calls == 2
    assert native_resident_admission_snapshot()["transient_retries"] >= 1


def test_native_resident_path_restarts_after_transient_transport_loss(monkeypatch, tmp_path) -> None:
    executable = tmp_path / "guard-runtime"
    executable.write_bytes(b"fixture")
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    calls = 0

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.native_runtime_resident._resident_socket_path",
        lambda guard_home, identity_sha256: guard_home / f"{identity_sha256[:8]}.sock",
    )

    def send(self, payload: bytes, *, timeout_seconds: float) -> bytes | None:
        nonlocal calls
        del self, payload, timeout_seconds
        calls += 1
        return None if calls == 1 else b'{"status":"ready"}'

    monkeypatch.setattr(_ResidentService, "_send", send)
    monkeypatch.setattr(_ResidentService, "_ensure_started", lambda self, *, timeout_seconds: True)
    result = resident_native_request(
        executable=executable,
        identity_sha256="a" * 64,
        guard_home=guard_home,
        environment={},
        payload=b'{"operation":"health"}',
        timeout_seconds=1,
    )

    assert result == b'{"status":"ready"}'
    assert calls == 2


def test_native_resident_path_does_not_retry_refused_start(monkeypatch, tmp_path) -> None:
    executable = tmp_path / "guard-runtime"
    executable.write_bytes(b"fixture")
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    starts = 0

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.native_runtime_resident._resident_socket_path",
        lambda guard_home, identity_sha256: guard_home / f"{identity_sha256[:8]}.sock",
    )

    def ensure_started(self, *, timeout_seconds: float) -> bool:
        nonlocal starts
        del self, timeout_seconds
        starts += 1
        return False

    monkeypatch.setattr(_ResidentService, "_send", lambda self, payload, *, timeout_seconds: None)
    monkeypatch.setattr(_ResidentService, "_ensure_started", ensure_started)
    result = resident_native_request(
        executable=executable,
        identity_sha256="b" * 64,
        guard_home=guard_home,
        environment={},
        payload=b'{"operation":"health"}',
        timeout_seconds=1,
    )

    assert result is None
    assert starts == 1


def test_native_admission_never_retries_integrity_failure() -> None:
    calls = 0

    @native_resident_admission
    def request(*, operation: str) -> str:
        nonlocal calls
        calls += 1
        raise RuntimeError("native manifest integrity mismatch")

    with pytest.raises(RuntimeError, match="integrity"):
        request(operation="command_model")
    assert calls == 1


def test_native_admission_is_bounded_under_flood() -> None:
    release = threading.Event()
    entered = threading.Event()

    @native_resident_admission
    def request(index: int, *, operation: str) -> int:
        entered.set()
        release.wait(timeout=2)
        return index

    with ThreadPoolExecutor(max_workers=96) as executor:
        futures = [executor.submit(request, index, operation="command_model") for index in range(96)]
        assert entered.wait(timeout=1)
        time.sleep(0.05)
        release.set()
        results: list[int] = []
        rejected = 0
        for future in futures:
            try:
                results.append(future.result(timeout=2))
            except NativeResidentAdmissionError:
                rejected += 1
    snapshot = native_resident_admission_snapshot()
    assert snapshot["high_water_data"] <= 60
    assert rejected == snapshot["rejected_data"] or snapshot["rejected_data"] >= rejected
    assert len(results) + rejected == 96


def test_lifecycle_capacity_is_reserved_when_data_capacity_is_busy() -> None:
    release = threading.Event()
    started = threading.Barrier(61)

    @native_resident_admission
    def data(index: int, *, operation: str) -> int:
        started.wait(timeout=3)
        release.wait(timeout=3)
        return index

    @native_resident_admission
    def health(*, operation: str) -> str:
        return operation

    with ThreadPoolExecutor(max_workers=61) as executor:
        futures = [executor.submit(data, index, operation="command_model") for index in range(60)]
        started.wait(timeout=3)
        assert health(operation="health") == "health"
        release.set()
        assert sorted(future.result(timeout=3) for future in futures) == list(range(60))
