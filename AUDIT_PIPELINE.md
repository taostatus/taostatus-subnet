# Operational Audit Pipeline — Status & Review

*For review by the co-developer.* This documents the operational (real-target)
audit pipeline for the SN104 security track: what it is, what is **built and
tested**, what is **remaining**, and the security properties to review.

---

## 1. The vision

Beyond the sandbox benchmark (which only *vets* agents), the subnet earns by
auditing **real customer targets**:

```
Customer buys ONE run of an agent  ──▶  marketplace backend queues the job
                                             │
   Validator pulls the job  ◀────────────────┘
      │  runs the vetted agent against the real target, in isolation, measured
      │  validates the result (replay-confirm, safety)
      ▼
   findings → customer     +     measured report → emission to the miner (next epoch)
```

- Customers never receive the agent (IP stays private); they get a **session/run**.
- The agent runs **only on our side**, kernel-isolated, reaching **only** the
  one validated target.
- Emission is driven by **validated** real audits (confirmed + safe), not by the
  benchmark. See `CICD_AUDIT_FLOW.md` for the customer-facing picture.

---

## 2. Architecture

```
 target_guard ──▶ validate + PIN the target IP (anti-SSRF)
      │
 audit_runner ──▶ egress_proxy container (pinned target, measuring, hardened)
      │           + agent container on a --internal network, DNS blackholed,
      │             pointed at the proxy  (gVisor, cap-drop, read-only)
      │
      ├─ collect: findings + proxy stats + gVisor behaviour
      ├─ certify safety (fail-closed if monitoring missing)
      ├─ replay_confirm: reproduce the claimed injection on the pinned target
      └─ score_audit: correctness-anchored, gate-first  ──▶ measured report

 audit_client / audit_loop ──▶ pull jobs from the backend, run, post results
```

---

## 3. What is BUILT and TESTED

All of the following is implemented with unit tests, and the **full chain is
proven end-to-end on the isolation host** (real docker: `confirmed=true`,
`safe=true`, `score=1.0`, agent reached the target *only* through the proxy).

| Component | File | What it does | Tests |
|---|---|---|---|
| **Target guard** | `secqurityVali/target_guard.py` | Validate a customer URL; reject private/loopback/link-local/metadata/IPv4-mapped/encoded/userinfo-bypass; **pin** the resolved IP (DNS-rebinding safe) | 32 |
| **Egress proxy** | `secqurityVali/egress_proxy.py` | Trusted reverse-proxy: forwards only to the pinned target, measures, no-redirect-follow, caps (rate/body/requests/concurrency), refuses non-public target | 14 + docker |
| **Sandbox DNS fix** | `secqurityVali/job.py` | Closes a DNS-exfiltration leak: `--internal` + `--dns` still resolved external names via docker's embedded resolver; now a blackhole `/etc/resolv.conf` is bind-mounted | (54 job/pipeline) |
| **Audit runner** | `secqurityVali/audit_runner.py` | Composes the whole audit; `score_audit` is pure + gate-first (unsafe / uncertifiable / unconfirmed ⇒ 0) | 14 |
| **Replay confirm** | `secqurityVali/replay_confirm.py` | Canary-free confirmation: replay the agent's payload (canary reproduction) + multi-context boolean differential; replay only ever hits the pinned target | 11 |
| **Audit client** | `masxai/audit_client.py` | Validator↔backend: claim_next_job / post_result; bearer; best-effort, never raises; fail-closed env | 9 |
| **Audit loop** | `secqurityVali/audit_loop.py` | `process_audit_job`: **only vetted agents run operationally**; unavailable/malformed ⇒ failed result, never a crash | 7 |

**~87 new unit tests, all green**, plus the live end-to-end on the VPS.

### Backend (separate repo `taostatus/marketplace-server`, already pushed + live)
- `POST /api/runs` (buy a run, reserves the agent), `GET /api/runs/{id}` (session
  polling), `GET /api/runs`; `available` flag on catalog agents.
- Internal: `GET /api/internal/next-job`, `POST /api/internal/runs/{id}/result`.
- 31 tests; deployed and live at `http://169.58.6.18:8099`. See that repo's
  `docs/AUDIT_API.md` (for the frontend dev).

---

## 4. Security properties to review (each is tested)

- **Agent isolation** — agent on docker `--internal`: no route to the internet,
  cloud metadata (169.254.169.254), private ranges, the host, or any other host;
  only the proxy. Verified on the isolation host.
- **No DNS exfiltration** — DNS fully disabled (blackhole resolv.conf); the
  `--dns`-only approach was shown to still leak and is fixed.
- **Anti-SSRF (customer-supplied target)** — `target_guard` rejects internal /
  metadata / mapped / encoded / userinfo-bypass targets; the IP is pinned and the
  proxy dials only that pinned IP (TOCTOU-safe). The proxy also refuses a
  non-public target (defence in depth).
- **Egress is trusted-minimal** — the only thing with outbound reach is our small
  proxy, which forwards only to the one pinned target and never follows redirects.
- **Fail-closed safety** — if gVisor monitoring didn't capture a run, the run is
  treated as unsafe and scores 0.
- **Emission integrity** — an unconfirmed, unsafe, or uncertifiable run scores 0;
  only vetted agents may ever run operationally.
- **Robustness** — backend/network failures never raise into the validator; every
  run tears down all containers/networks/temp files (no leaked egress).

---

## 5. What is REMAINING

1. **Live validator wiring (Step 3a-ii).** A background loop in
   `neurons/security_validator.py` that:
   - opens the audit client, polls `claim_next_job`;
   - implements `is_vetted(agent_id)` (agent passed the admission gate) and
     `resolve_agent(agent_id)` (hotkey → uid → query the miner's
     `SecurityAgentSynapse` → decrypt → load the image);
   - calls `process_audit_job` and posts the result;
   - runs in the background so it never blocks weight-setting (vtrust).
2. **Emission (Step 3b).** Per-epoch scoring from validated audit runs → weights
   (one report ⇒ one epoch's emission, nothing carries over) — mirroring the
   LLM-key epoch machinery.
3. **Replay-confirm hardening.** The boolean-differential covers blind SQLi on
   real targets; worth broadening (error-based, more contexts) and calibrating
   against real apps.
4. **Connector mode (internal targets).** `allow_private` path exists but the
   customer-installed connector (Model B) is not built.
5. **Customer onboarding.** Account / API key / target-ownership verification
   (the minimal dev-implicit + 1-click flows) — backend side.
6. **Scoring calibration.** `TARGET_TIME_MS` / `TARGET_REQUESTS` and the axis
   weights are reasonable defaults, to be tuned on real data.

---

## 6. Running the tests

```bash
# subnet (audit pipeline) — from the repo root, in the project venv:
python -m pytest tests/test_target_guard.py tests/test_egress_proxy.py \
  tests/test_replay_confirm.py tests/test_audit_runner.py \
  tests/test_audit_loop.py tests/test_audit_client.py -q

# backend (separate repo): in its venv -> pytest -q
```

---

## 7. Open questions for review

- **Agent resolution for an operational job** — re-query the miner each run, or
  cache the decrypted image from the last vetting round? (trade-off: freshness vs
  load/storage, and the security of holding decrypted images.)
- **Multi-validator consensus** — on mainnet with several validators, should the
  *run* stay in the validator (job sharding) or move to a shared backend so all
  validators score the same report (Yuma-consensus-safe)? Today (single testnet
  validator) the validator-runs model is simplest.
- **Replay confirmation** on real targets without any canary — is the boolean
  differential strong enough, or do we want a richer confirmer?
