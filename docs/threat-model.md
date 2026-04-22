# Threat model — Zero-trust Kubernetes security pipeline

## Overview

This document maps each security layer in the pipeline to the threats it mitigates,
the attack it would have stopped in real-world incidents, and the MITRE ATT&CK
technique it covers.

---

## Threat layers

### Layer 1 — Source & image scanning (Trivy)

| Threat | How Trivy stops it |
|---|---|
| Known CVE in base image | Fails CI build on CRITICAL severity |
| Hardcoded secrets in code | Trivy secret scanning on filesystem |
| Misconfigured Dockerfile | Trivy misconfiguration detection |

**Real incident this would have stopped:** The 2021 Log4Shell incident — Trivy would
have detected the vulnerable log4j version in the SBOM and blocked the image push.

---

### Layer 2 — Software Bill of Materials (Syft)

| Threat | How SBOM stops it |
|---|---|
| Unknown dependency introduced | Every package is inventoried |
| Supply chain audit requirement | SPDX JSON is a compliance artifact |
| Future CVE in a known package | SBOM can be re-scanned at any time |

**Standard:** Meets NIST SP 800-218 and US Executive Order 14028 SBOM requirements.

---

### Layer 3 — Image signing (Cosign / Sigstore)

| Threat | How signing stops it |
|---|---|
| Tampered image in registry | Signature mismatch = admission blocked |
| Image substitution attack | Cryptographic identity tied to GitHub Actions OIDC |
| Unsigned image deployed | Gatekeeper policy rejects the pod |

**Real incident:** The 2020 SolarWinds attack involved tampered build artifacts.
Cosign signing with a verified OIDC identity would have made this detectable.

---

### Layer 4 — Admission control (OPA Gatekeeper)

| Policy | Threat mitigated |
|---|---|
| No root containers | Privilege escalation if container is compromised |
| No privileged containers | Full node compromise via privileged pod |
| Require resource limits | Denial-of-service via resource exhaustion |
| Allowed registries only | Pulling malicious images from public registries |
| No latest tag | Non-deterministic deployments, hidden image swaps |

**MITRE ATT&CK coverage:** T1611 (Escape to Host), T1525 (Implant Internal Image)

---

### Layer 5 — Runtime detection (Falco)

| Rule | Threat mitigated | MITRE technique |
|---|---|---|
| Shell spawned in container | Remote code execution via web shell | T1059 |
| Write to /etc, /bin, /sbin | Persistence via file system modification | T1546 |
| Outbound unexpected connection | C2 communication / data exfiltration | T1041 |
| /etc/passwd read | Credential access / user enumeration | T1003 |
| Package manager run | Attacker installing tools post-compromise | T1072 |

**Why runtime matters:** The first 4 layers prevent known-bad from being deployed.
Falco catches zero-day exploits and misuse *after* deployment — something static
analysis can never do.

---

## Attack scenario walkthrough

**Scenario:** Attacker finds an RCE vulnerability in the FastAPI app.

1. Attacker sends a malicious request → gets code execution inside the container.
2. Attacker tries `pip install` to install tools → **Falco fires rule 5**, Slack alert sent.
3. Attacker tries to spawn `/bin/bash` → **Falco fires rule 1**, CRITICAL alert sent.
4. Attacker tries to read `/etc/passwd` → **Falco fires rule 4**, WARNING alert sent.
5. Attacker tries to push a backdoored image → **Cosign signature fails**, Gatekeeper blocks the pod.

Result: Attacker gets 0 persistence, every step is logged, security team is alerted in real time.

---

## What this pipeline does NOT cover

- **mTLS between services** — add Istio or Linkerd for service mesh zero-trust
- **Secrets management** — add HashiCorp Vault or External Secrets Operator
- **Network policies** — add Cilium or Calico NetworkPolicy resources
- **RBAC hardening** — restrict ServiceAccount permissions per workload

These are natural extensions to propose when discussing this project in interviews.
