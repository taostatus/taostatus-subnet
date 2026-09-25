**

# TaoStatus MVP: Integrating the Isolated Execution Architecture into the Existing Submission Flow

## Document Purpose

This report describes how the existing TaoStatus miner-submission and validator-execution flow evolves to incorporate the isolated (gVisor + Docker) execution architecture described previously. It documents the end-to-end pipeline : from miner packaging through validator evaluation and cleanup : at the level of component responsibilities, interfaces, and sequencing. It does not redesign the isolation model itself and does not provide a shell-command tutorial; it explains how the current working flow (Miner → submits image reference → Validator API → pulls → verifies → runs → verdict) is extended so that "runs it" becomes a properly isolated execution stage rather than a single unguarded step.

## 1\. Miner-Side Flow

### 1.1 Packaging the Security Agent

A miner's responsibility is limited to producing a well-formed, self-contained Docker image containing their SQL injection testing agent. The agent itself is expected to:

-   Accept connection details for a target application at runtime (host/port, provided by the validator at container start, not hardcoded). 

-   Perform its SQL injection testing logic against that target. 

-   Write its findings to a defined output location in a structured, machine-readable format (e.g. JSON) rather than free-form text or logs alone. 

The miner is not responsible for and should not attempt to manage networking, database provisioning, or anything related to the isolation environment : the agent only needs to know how to reach a target it is told about and where to write results.

### 1.2 Building, Tagging, and Publishing the Image

The miner builds the image using standard Docker tooling and publishes it to a container registry (the same registry infrastructure already used in the current submission flow). The image should be:

-   Tagged with a specific, immutable version rather than a mutable tag such as latest, since the validator will pin execution to a specific digest. 

-   Published to a registry reachable by the validator (public registry or a registry TaoStatus already integrates with). 

No changes are required to how miners build and push images : this stage is unchanged from the current flow.

### 1.3 Submitting the Image Reference to the Validator

The miner submits the image reference to the Validator API exactly as in the existing flow. The only addition is that the submission should resolve to (or the validator should resolve it to) an immutable image digest, not just a tag, so that the exact image contents are pinned before execution.

### 1.4 Additional Information Submitted Alongside the Image

To support isolated execution, the miner's submission should include, alongside the image reference:

| Field | Purpose |
| --- | --- |
| Image digest (or resolvable tag) | Pins the exact image version to be pulled and executed |
| Target application type/identifier | Tells the validator which disposable target app + DB combination to provision for this job |
| Expected agent invocation contract | How the validator should pass target connection info and output path to the container (e.g. environment variables, CLI args) |
| Declared resource expectations (optional, MVP-light) | Basic hint for reasonable CPU/memory limits; validator still enforces hard caps regardless |

This is metadata carried alongside the existing submission payload : it does not change the transport mechanism, only what is included in it.

### 1.5 Fit with the Existing Miner/API Interaction

The miner-to-Validator-API interaction is unchanged in shape: submit a reference, receive an acknowledgment, later receive a verdict. What changes is entirely on the validator's side of that boundary : the miner is unaware of, and unaffected by, the isolation mechanics described in the following sections.

## 2\. Validator Submission and Image Handling

### 2.1 Receiving the Submission

The Validator API receives the submission through its existing endpoint, unchanged. It records the submitted image reference and accompanying metadata (Section 1.4) against a new job record.

### 2.2 Obtaining the Image

The validator pulls the image from the registry using the pinned digest, exactly as in the current flow's "Validator pulls image" step. This remains a normal registry pull : no isolation is needed for the pull operation itself.

### 2.3 Image Verification and Digest Handling

Before execution, the validator performs its existing verification step, with the digest now treated as the authoritative identifier for the job:

-   Confirm the pulled image's digest matches what was submitted (protects against tag mutation between submission and pull). 

-   Apply any existing basic image checks already part of the current flow (e.g. size sanity checks). 

This verification step is unchanged in kind from the current flow : it is simply anchored to a digest rather than a tag, which is a prerequisite for safe repeated execution later (reproduction, Section 5).

### 2.4 Transition Point: Normal Workflow → Isolated Execution

The existing flow's "runs it" step is where the architecture changes. Once the image is pulled and verified, control passes from the validator's normal request-handling logic to a distinct job execution component responsible for isolated execution. This is the explicit handoff point:

\[Existing\] Validator API → Image Pull → Verification

                                   │

                                   ▼

\[New\]                    Isolated Job Execution

Everything before this point (API handling, pulling, verifying) is unchanged. Everything after it is new: the image is no longer just "run" : it is run inside a freshly created, isolated job environment, described next.

## 3\. Creating the Isolated Job

### 3.1 Fresh Sandbox per Submission

For each validated submission, the validator's job execution component creates a new, disposable job environment. Nothing is shared or reused between submissions : this is a deliberate simplicity choice for the MVP, avoiding any need for a persistent sandbox pool.

### 3.2 Components of a Job

| Component | Role | Origin |
| --- | --- | --- |
| Miner agent container | Runs the verified miner image; performs SQLi testing against the target | The submitted, pulled, verified image |
| Target application container | Disposable application instance the agent tests against | Validator-provided, standardized image selected based on the miner's declared target type |
| Target database container | Backing database for the target application | Validator-provided, standardized image, paired with the target application |
| Private per-job network | Connects agent, target app, and target DB; has no route to the validator host or internet | Created fresh for this job |

### 3.3 Role of Docker + gVisor

Each of the three containers (agent, target app, target DB) is started using Docker with the runsc (gVisor) runtime rather than the default runtime. This is the same primitive used throughout : the job creation step is simply "start these three containers, all under gVisor, all attached to this job's private network." No new orchestration mechanism is introduced; this is standard Docker container creation with a non-default runtime flag and a dedicated network.

### 3.4 Dynamic versus Persistent Components

| Created fresh per job (dynamic) | Persistent on the validator host |
| --- | --- |
| Miner agent container | Docker daemon + gVisor (runsc) runtime installation |
| Target application container | Standardized target application/database images (pulled once, reused as the base for each job's containers) |
| Target database container | Validator API and job orchestration logic |
| Private per-job network | Registry credentials/configuration |
| Job-specific output directory | Host-level resource limits/policies applied to all jobs |

This distinction matters for implementation: the validator host maintains a small set of long-lived infrastructure (Docker itself, gVisor, the base target images, the orchestrator process), while every individual job is entirely disposable state layered on top of that infrastructure.

## 4\. Actual SQL Injection Testing Flow

### 4.1 Agent-to-Target Communication

Once the job's containers are running, the miner agent communicates with the target application over the private per-job network using standard network calls (e.g. HTTP requests to the target application's exposed port). The validator passes the target's address to the agent at container start (via the invocation contract described in Section 1.4) : the agent does not discover or configure this itself.

### 4.2 Origin of the Target Application and Database

The target application and database are not provided by the miner. They are standardized, validator-maintained images selected based on the target type declared in the submission (Section 1.4). This ensures every miner is tested against a known, consistent, disposable target rather than something miner-controlled, which would undermine the integrity of the evaluation.

### 4.3 Isolation During Testing

While the agent performs its SQLi testing:

-   It can reach only the target application and database on its job's private network. 

-   It has no route to the validator host, no route to the internet, and no route to any other job's network (each job's network is created and destroyed independently). 

-   It runs under gVisor, so even if the agent attempts to exploit its own container environment, it is contained by gVisor's syscall interception rather than reaching the host kernel directly. 

This is the same isolation model described in the architecture document : this section simply confirms it applies unchanged at the point where actual testing traffic flows.

### 4.4 Returning Findings to the Validator

The agent writes its findings to a mounted output location (a file, not a live connection back to the validator process). Once the agent's execution completes, the validator's job execution component reads this file directly from the filesystem boundary : the agent has no ability to push data into the validator process itself; the validator is always the one initiating the read.

## 5\. Validator Evaluation

### 5.1 Consuming Findings as Data

The validator reads the agent's output file and parses it strictly as structured data (e.g. validating it against an expected JSON schema). At no point is the content of this file executed, evaluated, or used to construct commands. This is the point in the flow where the existing "returns verdict" step begins, now fed by isolated job output rather than direct container output trusted implicitly.

### 5.2 Reproducing a Reported Vulnerability

If a finding needs to be confirmed, the validator does not re-trust the original agent run : it triggers a separate reproduction job. This reproduction job follows the same job-creation pattern described in Section 3: a fresh target application and database are provisioned, a fresh private network is created, and the miner's reported reproduction steps are replayed against this new target instance.

### 5.3 Reproduction Must Not Run on the Validator Host Directly

This is a firm constraint carried over from the architecture: whatever executes the miner's reproduction steps : whether that is a structured replay of requests/payloads or, if necessary, re-execution of a miner-provided script : must do so inside the same isolated container/network model, never directly on the validator host process. The reproduction stage is, from an isolation standpoint, a second instance of the same job pattern, not a shortcut.

## 6\. Job Completion and Cleanup

### 6.1 Successful Completion

When the agent completes and findings have been read and scored, the job execution component tears down all job resources: the agent, target application, and target database containers are stopped and removed, the private network is deleted, and any temporary output files are cleared after the validator has consumed them.

### 6.2 Failure

If the agent container exits with an error, produces malformed output, or otherwise fails, the same teardown sequence runs : job resources are not left running or retried automatically as part of the MVP flow. The validator records the failure outcome and proceeds to clean up exactly as in the success path.

### 6.3 Timeout

The job execution component enforces a wall-clock timeout independent of container-level resource limits. If a job exceeds this timeout (e.g. an agent that hangs or attempts a denial-of-service against its own container), the component forcibly stops the containers and proceeds to the same cleanup sequence.

### 6.4 Cleanup Scope

Cleanup always includes:

-   Removal of the agent, target application, and target database containers. 

-   Removal of the job's private network. 

-   Removal of job-specific temporary files/output directories. 

This teardown is unconditional : it runs regardless of whether the job succeeded, failed, or timed out, so no job-specific state persists past its own lifecycle.

### 6.5 Starting the Next Job Clean

Because nothing from a job is reused or retained, the next submission's job creation step (Section 3) always begins from the same baseline: the persistent validator-host infrastructure (Docker, gVisor, base target images, orchestrator) plus entirely fresh, newly created job resources. No job can inherit state, network reachability, or leftover containers from a prior job.

## 7\. Overall End-to-End Flow

Miner

  │  (builds, tags, publishes agent image)

  ▼

Image Registry

  │  (miner submits image reference/digest + metadata)

  ▼

Validator API

  │  (existing submission handling, unchanged)

  ▼

Image Pull / Verification

  │  (digest-pinned pull, existing verification logic)

  ▼

Isolated Job Creation

  │  (fresh private network + target app + target DB provisioned)

  ▼

gVisor Agent + Target + DB

  │  (agent tests target over private network, isolated from host/other jobs)

  ▼

Findings

  │  (written to file, read by validator as data only)

  ▼

Validator Evaluation

  │  (scoring; reproduction re-runs in a new isolated job if needed)

  ▼

Verdict

  │  (returned via existing Validator API response path)

  ▼

Cleanup

  (containers, network, temp files destroyed; next job starts clean)

This diagram represents the same high-level submission-to-verdict flow already in place today, with the isolated execution stage (job creation → gVisor agent/target/DB → findings) inserted at the point where the current system simply "runs" the image. All other stages of the existing pipeline remain structurally unchanged.

**