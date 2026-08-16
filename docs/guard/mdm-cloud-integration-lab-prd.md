# PRD: HOL Guard multi-device MDM Cloud integration hardening

## Status

Provider-neutral implementation and verification are complete when the focused contracts, real-HTTP process-restart test, non-root Docker lab, report checksum, security scan, and release branch checks are green. Native and commercial-provider certification remains a separate, explicitly unevaluated release gate.

## Problem

Portable MDM contract tests do not prove that several independent HOL Guard devices can enroll, receive Cloud-managed desired state, survive partial rollout and network faults, durably acknowledge application, publish monotonic health evidence, recover after process failure, and execute only typed remediation. A green unit suite is not sufficient when failures can occur between Cloud persistence, delivery, local atomic writes, acknowledgement delivery, evidence verification, or restart.

## Goal

Provide a deterministic integration environment that uses real HTTP, durable Cloud state, unique device keys, two isolated workspaces, signed configuration, a fault-injection proxy, four endpoint runtimes, process restarts, and a fleet orchestrator. The same security invariants must run quickly in-process and as separate Docker services in CI.

## Users

- Security engineering validating endpoint-management guarantees.
- CISOs and CSOs relying on fleet posture and rollout evidence.
- Release engineers certifying HOL Guard 3.0.
- Adapter authors mapping Intune, Jamf, Kandji, Workspace ONE, or another MDM to the vendor-neutral contract.

## Principles

1. Device identity is independent of user identity and network location. Every runtime request is bound to the device key, workspace, installation generation, HTTP method, path, body hash, time, and monotonic sequence.
2. Desired state is declarative. Cloud signs a complete configuration envelope; devices validate and converge rather than accepting an arbitrary command stream.
3. Fleet assignment is per device. A canary may skip global revisions, so the predecessor hash is recorded per assignment rather than assumed globally.
4. Delivery is at least once. Acknowledgements, health evidence, and remediation results use durable FIFO outboxes and exact Cloud idempotency.
5. Local enforcement survives Cloud failure. A partition never weakens the last known good managed policy.
6. Local execution is not recovery proof. A remediation remains awaiting evidence until a later healthy report verifies it.
7. Native transport certification is distinct from provider-neutral correctness.

## Architecture

The Compose project contains:

- `volume-init`: grants the fixed unprivileged runtime identity access only to named state and evidence volumes.
- `cloud`: SQLite-backed enrollment, assignment history, acknowledgement, health, remediation, and hash-chained audit service.
- `proxy`: deterministic partitions, delay, throttling, forced status, connection drops, lost success responses, corruption, truncation, malformed JSON, stale replay, and ETag removal.
- `device-a`, `device-b`, `device-c`: independent machines in the alpha workspace.
- `device-d`: an independent machine in the beta workspace.
- `orchestrator`: publishes baseline and canary policy, injects failures, drives recovery, validates tenant isolation, and writes bounded evidence.

The network is internal, has no host ports, mounts no Docker socket, drops capabilities, uses read-only root filesystems and bounded tmpfs, applies health-gated startup, and places every device on a separate persistent volume. Runtime services use fixed UID and GID `10001`.

## Security contracts

### Enrollment

Enrollment is one time and bound to workspace, device, installation generation, and P-256 public key. Cloud stores only a SHA-256 token digest. Token replay, public-key cloning, and identity collision fail closed.

### Request proof

Every post-enrollment request is signed by the device key. The proof covers method, path, body hash, request time, and sequence. Cloud rejects missing proof, bad signatures, stale time, wrong workspace or generation, and every sequence not greater than the stored sequence.

### Configuration

Cloud signs exact `hol-guard-mdm-cloud-config.v1` envelopes with RSA-PSS SHA-256. The envelope binds identity, revision, validity, policy, policy hash, predecessor hash, rollback metadata, and signing key. ETags include revision and policy hash so a same-content newer revision remains observable. The device verifies the envelope and invokes the production `hol-guard-mdm-policy.v1` parser before writing policy.

### Atomic apply and recovery

The device persists a pending record, refuses symlink destinations, atomically replaces the policy file with owner-only permissions, saves a last-known-good copy, commits its revision checkpoint, and queues an acknowledgement. A crash after policy replacement is recovered from the pending record without losing the acknowledgement.

### Acknowledgements and health

Cloud retains per-device assignment history, so a delayed acknowledgement remains valid after a newer assignment is published. Exact duplicate request IDs are accepted idempotently; semantic conflicts fail. Health is sequence-bound, references a real assigned revision and policy hash, and stays in a durable outbox while offline.

### Remediation

Cloud can issue only `install`, `integrity-scan`, `policy-refresh`, `repair`, `service-register`, or `version-converge`, each with a strict parameter schema, bounded validity, bounded attempts, and idempotency key. Arbitrary commands, scripts, shells, URLs, credentials, and unknown fields are rejected. Exact retries return the stored job. Reusing an idempotency key with different semantics or colliding on a job ID returns conflict rather than a phantom job.

A successful endpoint result moves the job to `awaiting_evidence`. A later healthy, identity-bound report is required before Cloud marks the job succeeded.

## Required scenarios

The orchestrator proves at least 50 named assertions, including:

- Four independent enrollments and unique keys across two workspaces.
- One-time token replay and cloned-key rejection.
- Administrative authorization, duplicate-key JSON rejection, and body-size limits.
- Tenant-isolated state, policy targeting, and remediation.
- Baseline rollout and one-device canary rollout.
- Same-content newer revision delivery.
- Per-device predecessor chains across skipped revisions.
- Historical acknowledgement delivery after a superseding assignment.
- Lost success response, `429`, `503`, and partition recovery without evidence loss.
- Configuration corruption, truncation, malformed JSON, missing ETag, and stale replay rejection.
- Explicit signed rollback with monotonic revision.
- Request-proof replay, workspace substitution, and clock-skew rejection.
- Crash after policy write and durable checkpoint recovery.
- Permission, content, missing-file, and symlink tamper detection.
- Exact remediation idempotency, conflict handling, fixed action coverage, and arbitrary-command rejection.
- Evidence-gated remediation recovery.
- Audit redaction and tamper-evident chain validation.
- Cloud and endpoint process restart with persisted identities, signing key, request sequence, policy, outbox, and audit state.

## Evidence

The lab emits `hol-guard-mdm-cloud-integration-lab.v1` with bounded named steps, pass status, duration, evidence, workspace, and an explicit native-certification section. CI validates the JSON Schema, verifies a SHA-256 checksum, uploads the report and bounded logs, scans the lab configuration, and always removes containers, networks, and volumes.

## Acceptance criteria

- Contract, persistence, schema, registration, and real-HTTP restart tests pass.
- The in-process integration stops and recreates all servers against persistent state.
- The non-root Docker Compose project passes at least 50 assertions.
- Every report step passes and its checksum verifies.
- The report states native certification is `not-evaluated`.
- No arbitrary remote command surface exists.
- Cloud state and evidence contain no enrollment token, private key, credential, or unbounded error material.
- Trivy reports no HIGH or CRITICAL lab misconfiguration.
- The test-suite ratchet is updated to the exact reviewed inventory.
- The task ledger retains at least 300 unique tasks and preserves unfinished native/provider gates honestly.

## Native certification boundary

This lab does not certify APNs, Apple supervision, Automated Device Enrollment, Secure Enclave behavior, Windows CSP or SyncML enrollment, SYSTEM context, Authenticode, WDAC, production package signing, notarization, or a commercial provider's retries, RBAC, scheduling, and audit export. Those remain release-candidate tests on native platforms or provider trials and must never be inferred from Docker success.
