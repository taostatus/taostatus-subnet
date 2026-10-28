# Security Audits as a CI/CD Step — Delivery & Emission Approach

*How customers use the subnet's security agents, how a trustworthy report is
produced, and how that report drives on-chain emission — without ever exposing
an agent's code.*

---

## The problem we're solving

For the security track to pay emission, three things must be true at once:

1. **Customers must actually use the agents** on their real targets — that usage
   is what produces a *report*.
2. **The agent's code must stay private** — it is the miner's IP; peers or
   customers must not be able to copy it. (This is why agents are encrypted and
   only the validator can decrypt them.)
3. **The report must be trustworthy** — speed, reliability, error-rate and real
   findings have to be *measured by us*, not self-claimed, because emission is
   paid from it.

A naive "give the customer the agent to run" breaks (2) and (3): the code leaks,
and the customer could fake the report. So we **don't give them the agent — we
give them the audit result, as a service.** The agent runs on *our* side; the
customer only sends us a target and gets back findings.

---

## The core idea: "security audit as a pipeline step"

This is the same pattern DAST tools like Snyk and StackHawk use: the customer
adds one step to their existing CI/CD pipeline. On every pull request / deploy,
that step asks **our** backend to audit the app that was just built. Our backend
runs a vetted agent against it and returns a pass/fail gate plus findings.

The customer never receives the agent. Their pipeline just calls our API.

```
 Developer pushes code
        │
        ▼
 CI pipeline builds + deploys a staging / preview URL   (e.g. https://pr-123.staging.app)
        │
        ▼
 Pipeline step:   taostatus-audit --target $STAGING_URL --token $CUSTOMER_KEY
        │  (just an HTTPS call to our backend — no agent on the runner)
        ▼
 ┌──────────────────────── OUR ORCHESTRATION BACKEND ────────────────────────┐
 │  1. decrypt the vetted agent (only we hold the key)                        │
 │  2. run it in an isolated sandbox against the customer's target            │
 │  3. MEASURE the run: speed, reliability, error-rate, findings             │
 └───────────────┬───────────────────────────────────────┬───────────────────┘
                 │                                         │
                 ▼                                         ▼
   Customer gets: findings report            Validator gets: measured report
   (build FAILS if a critical vuln)          per (agent/miner, epoch)
                                                         │
                                                         ▼
                                            score the report → set weights
                                                         │
                                                         ▼
                              EMISSION to the miner whose agent ran
                              (next epoch, once per report)
```

---

## Why this satisfies all three constraints

| Constraint | How CI/CD-on-hosted-backend satisfies it |
|---|---|
| **Customer uses the agent** | Every PR/deploy triggers a real audit of their real app. |
| **Agent code stays private** | The agent is decrypted and run only inside *our* backend. The customer's CI runner never sees it — it only makes an API call. |
| **Report is trustworthy** | *We* run and measure the agent, so speed/reliability/error-rate/findings are observed by us, not claimed by the customer. |

---

## Why it's the right fit for the emission model

The emission design is: **a report in epoch N pays emission in epoch N+1,
once; the next payout needs a fresh report.** (Same as the LLM-key track.)

CI/CD produces exactly the input that model wants: a **steady stream of fresh
reports**. A team that audits on every pull request and deploy generates many
reports per day. So:

- Good agents that get used a lot earn continuously.
- An agent that stops being used stops earning — no coasting.
- Emission tracks *real operational value*, not a one-time benchmark.

A one-off "run the benchmark once" model can't do this; recurring CI usage can.

---

## What each party does

- **Customer / developer** — adds one audit step to their pipeline and provides
  a reachable target (usually the web-facing staging/preview URL) plus an API
  key. Gets back a security gate + findings.
- **Our orchestration backend** *(to build)* — holds the decryption key, runs
  vetted agents in isolated sandboxes against customer targets, measures each
  run, returns findings to the customer and a measured report to the validator.
- **Validator** *(port from the LLM-key track)* — collects reports per epoch,
  scores them (speed, reliability, error-rate), and sets on-chain weights so the
  right miner is paid next epoch.
- **Miner** — submits an encrypted agent; earns when its agent is the one doing
  real audits well.

> Vetting still matters: before an agent is ever allowed to touch a customer
> target, it must pass the **sandbox benchmark** (prove it can find a planted
> vulnerability + prove it is safe). The sandbox is the *admission gate*; real
> CI/CD usage is what *pays*.

---

## What a customer's integration looks like

A GitHub Actions example — the whole integration on the customer side is this
small, and no agent code is present:

```yaml
# .github/workflows/security-audit.yml
jobs:
  security-audit:
    runs-on: ubuntu-latest
    steps:
      - name: Deploy preview
        run: ./deploy-staging.sh            # produces $STAGING_URL

      - name: TaoStatus security audit
        run: |
          npx taostatus-audit \
            --target "$STAGING_URL" \
            --fail-on critical               # block the build on a real vuln
        env:
          TAOSTATUS_API_KEY: ${{ secrets.TAOSTATUS_API_KEY }}
```

`taostatus-audit` is a thin CLI that calls our backend
(`POST /audit { target, scope }`), waits for the result, prints findings, and
exits non-zero if the gate fails. That's the entire customer footprint.

---

## Scope boundary (what we start with vs. later)

- **Start:** hosted audit + CI/CD interface for **web-facing targets** (staging
  / preview URLs reachable from our backend). Covers the common case and needs
  no software inside the customer's network.
- **Later:** an optional **connector** the customer installs in their own
  network, so **internal / private targets** can be audited too — same backend,
  same agent-stays-private guarantee, just extended reach.

---

## What we need to build (summary)

1. **Orchestration backend** — the service that decrypts + sandbox-runs vetted
   agents against customer targets and measures them. *(new — the key piece)*
2. **CI/CD interface** — the `taostatus-audit` CLI / GitHub Action and the
   `POST /audit` API it calls. *(new)*
3. **Validator scoring + emission** — per-epoch report ingestion and scoring,
   ported from the proven LLM-key machinery. *(port)*
4. **Sandbox vetting** — already built; reused as the admission gate.
5. **Marketplace catalog** — already live; where customers browse agents.
