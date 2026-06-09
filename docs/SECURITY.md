# Security Policy — s3-put

> **Version:** 0.3.0
> **Last reviewed:** 2026-06-09
> **Classification:** Internal — Audit-Grade Documentation

---

## Table of Contents

- [Supported Versions](#supported-versions)
- [Reporting a Vulnerability](#reporting-a-vulnerability)
- [Threat Model](#threat-model)
- [Security Architecture](#security-architecture)
- [Credential Protection](#credential-protection)
- [Cryptographic Controls](#cryptographic-controls)
- [KMAC256 Integrity Tagging — Security Analysis](#kmac256-integrity-tagging--security-analysis)
- [Input Validation](#input-validation)
- [Output and Error Handling](#output-and-error-handling)
- [Audit Logging](#audit-logging)
- [Multipart Upload Safety](#multipart-upload-safety)
- [File System Safety](#file-system-safety)
- [Dependency Supply Chain](#dependency-supply-chain)
- [Known Vulnerabilities and Mitigations](#known-vulnerabilities-and-mitigations)
- [Compliance Control Mapping](#compliance-control-mapping)
- [Hardening Checklist](#hardening-checklist)
- [Accepted Risks](#accepted-risks)
- [Remediation Roadmap](#remediation-roadmap)

---

## Supported Versions

| Version | Status    | Security Updates |
|---------|-----------|------------------|
| 0.3.x   | Active   | Yes              |
| 0.2.x   | EOL      | No               |
| 0.1.x   | EOL      | No               |

Only the latest patch release of each minor version receives security updates.

---

## Reporting a Vulnerability

If you discover a security vulnerability in `s3-put`, please report it
**privately**.  Do not open a public issue.

1. Email: `security@<your-org-domain>`
2. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Affected version(s)
   - Potential impact assessment
3. You will receive an acknowledgement within **48 hours**.
4. A fix will be developed and released within **14 calendar days** for
   High/Critical severity findings.

---

## Threat Model

### Assets protected

| Asset | Description |
|-------|-------------|
| HMAC credentials | `accessKey` / `secretKey` in `~/.mc/config.json` |
| KMAC key | Hex-encoded key passed via `--kmac-key` CLI flag |
| Data in transit | File content between local filesystem and S3 endpoint |
| Data at rest (source) | Local files read by the application |
| Data at rest (remote) | Objects written to S3 buckets |
| Object integrity tags | `x-amz-meta-kmac256` metadata on uploaded objects |
| Audit trail | JSONL records emitted to stderr |
| Infrastructure topology | Endpoint URLs, bucket names, alias names, object keys |
| Multipart upload state | Upload IDs, part ETags during in-progress uploads |

### Trust boundaries

```
┌─────────────────────────────┐
│  Local filesystem           │
│  ~/.mc/config.json (0600)   │
│  Source files to upload      │
├─────────────────────────────┤
│  s3-put process             │  ← Trust boundary
│  ┌────────────────────────┐ │
│  │ KMAC256 compute        │ │  ← New in v0.3.0
│  │ (streaming, 8 KiB buf) │ │
│  └────────────────────────┘ │
├─────────────────────────────┤
│  TLS 1.3 (X25519MLKEM768)  │  ← Network boundary
├─────────────────────────────┤
│  S3-compatible endpoint     │
│  (MinIO / IBM COS / AWS)    │
└─────────────────────────────┘
```

### Threat actors considered

| Actor | Capability | Relevant controls |
|-------|-----------|-------------------|
| Local unprivileged user | Read config file, inspect process memory, read /proc/PID/cmdline | Config permission check (0600), SecretString zeroing; KMAC key visible in cmdline (accepted risk) |
| Network observer (passive) | Capture TLS traffic for later decryption | X25519MLKEM768 PQ KX, TLS 1.3 |
| Network attacker (active) | MITM, certificate substitution, response injection | CA bundle validation, certificate chain verification |
| Malicious endpoint | Return crafted responses, manipulate ETags | ETag validation in multipart completion, abort on failure |
| Supply chain attacker | Compromise a dependency crate | cargo audit, SBOM, dependency pinning |
| Data integrity attacker | Modify object content after upload | KMAC256 tag enables detection — any party with the key can recompute and compare |

---

## Security Architecture

### Process lifecycle

```
 1. Parse CLI arguments
 2. Validate input lengths (SI-10)
    a. Target string length (2,048 chars max)
    b. Part size minimum (5 MiB)
    c. Part count maximum (10,000)
    d. KMAC key hex decoding (fail-fast on invalid hex)
 3. Compute KMAC256 if --kmac-key is set
    a. Stream source file in 8 KiB chunks through Kmac::v256
    b. Finalize to 64 bytes (512 bits) — standard KMAC256 output
    c. Base64-encode → 88 characters
 4. Validate source file
    a. Must exist and be a regular file
    b. Multipart constraint pre-check
 5. Load ~/.mc/config.json
    a. Check file permissions (CWE-732)
    b. Enforce file size limit (CWE-400)
    c. Parse JSON → McConfig with SecretString fields
 6. Resolve alias, bucket, key
    a. Key derivation from source filename if target ends with '/'
    b. Sanitize error messages (CWE-209)
 7. Build HTTPS client
    a. rustls + aws-lc-rs with prefer-post-quantum
    b. Optional CA bundle (additive, not replacing)
 8. Build S3 client with timeout config
 9. Emit audit start record to stderr (CWE-778)
    a. Includes kmac_attached: true/false
10. Upload
    a. Single PutObject (file <= threshold)
       - Attach x-amz-meta-kmac256 if computed
    b. Multipart: CreateMultipartUpload → UploadPart × N → CompleteMultipartUpload
       - Attach x-amz-meta-kmac256 on CreateMultipartUpload
    c. On failure: AbortMultipartUpload + audit abort record
11. Emit result record to stdout (includes kmac256 if computed)
12. Emit audit completion record to stderr (includes kmac256 if computed)
13. SecretString fields zeroed on drop (CWE-316)
14. Process exits
```

---

## Credential Protection

### Storage

| Layer | Control | CWE |
|-------|---------|-----|
| Config file | `~/.mc/config.json` must be mode `0600` on Unix | CWE-732 |
| In-memory | `accessKey` / `secretKey` as `secrecy::SecretString` (zeroed on drop) | CWE-256, CWE-316 |
| Debug output | `SecretString` prints `[REDACTED]` | CWE-532, CWE-215 |
| Error messages | Hidden unless `--verbose` | CWE-209 |

### Residual risk

`Credentials::new()` accepts `String` (not zeroed on drop).  Upstream SDK
limitation.  Short-lived CLI; memory reclaimed on exit.

---

## Cryptographic Controls

### TLS configuration

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| TLS library | rustls 0.23.x | Memory-safe |
| Crypto provider | aws-lc-rs | NIST-validated, PQ support |
| Preferred KX | X25519MLKEM768 | Collect-now-harvest-later protection |
| Fallback KX | X25519, secp256r1, secp384r1 | Compatibility |
| Minimum TLS | 1.2 (rustls default) | PCI DSS 4.0 Req 4.2.1 |
| Certificate validation | Platform roots + optional PEM CA bundle | CWE-295 |
| FIPS mode | Optional (`--features fips`) | SC-13 |

---

## KMAC256 Integrity Tagging — Security Analysis

### New in v0.3.0

When `--kmac-key` is provided, `s3-put` computes NIST SP 800-185 KMAC256
with the **standard 512-bit output** (no truncation) and attaches the
base64-encoded result as `x-amz-meta-kmac256`.

### Cryptographic properties

| Property | Value |
|----------|-------|
| NIST standard | SP 800-185 (KMAC) |
| Variant | KMAC256 (`Kmac::v256`) |
| Underlying primitive | Keccak-1600 (sponge, capacity 512) |
| Security strength | 256-bit classical |
| Quantum security (Grover) | ~128-bit |
| Output length | **512 bits (64 bytes) — standard, untruncated** |
| Base64 output | 88 characters |
| Domain separation | Built-in customization parameter (S) per SP 800-185 |

### Why standard output (no truncation)

KMAC256 has a **standard output length of 512 bits** defined in SP 800-185.
Using the standard length:

- Matches the NIST specification exactly — no footnotes or justifications
- Avoids auditor questions about non-standard truncation
- 88 base64 characters fits well within the 2 KB S3 metadata limit
- 256-bit security is maintained regardless of output length

### Implementation details

| Aspect | Detail |
|--------|--------|
| Library | `tiny-keccak` v2.0 with `kmac` feature — pure Rust, ~200 lines |
| Constructor | `Kmac::v256(key, customization)` |
| Streaming | File read in 8 KiB chunks via `std::io::Read` — never fully buffered |
| Finalization | `kmac.finalize(&mut [0u8; 64])` — 64 bytes, standard output |
| Encoding | Base64 (standard alphabet, padded) via `base64` v0.22 |
| Key input | Hex-decoded from CLI `--kmac-key` via `hex` v0.4 |
| Customization | UTF-8 string from `--kmac-custom` (default: empty) |
| Metadata key | `x-amz-meta-kmac256` (auto-prefixed by SDK) |

### What the tag proves

| Property | Verified? |
|----------|-----------|
| File integrity | ✅ Any modification changes the KMAC output |
| Key authenticity | ✅ Only key holders can produce a valid tag |
| Domain separation | ✅ Different `--kmac-custom` → different tags |
| Non-repudiation | ❌ Symmetric — any key holder can produce a tag |
| Confidentiality | ❌ KMAC does not encrypt |

### Metadata persistence

| Operation | Tag preserved? |
|-----------|---------------|
| `CopyObject` with `metadata_directive: COPY` | ✅ Yes |
| `s3-mv` (server-side) | ✅ Yes |
| `CopyObject` with `metadata_directive: REPLACE` | ❌ No |
| Manual metadata update (`mc cp --attr` to self) | ❌ No |

### Key management considerations

| Concern | Risk | Mitigation |
|---------|------|------------|
| Key on CLI | Visible in `/proc/PID/cmdline` | Use env vars; planned: `--kmac-key-file` |
| Key in memory | `String` not zeroed on drop | Short-lived CLI; planned: `SecretString` |
| Key rotation | Old tags valid with old key | Retain old keys for verification |
| Key distribution | Shared secret | Use secrets managers |
| Empty key | Valid per SP 800-185 but no security | Document: use >= 32 bytes |

### Zero-cost when unused

When `--kmac-key` is not provided: no computation, no metadata, no output
field, `kmac_attached: false` in audit, zero runtime cost.

---

## Input Validation

| Input | Validation | Limit | CWE |
|-------|-----------|-------|-----|
| Target string | Max length | 2,048 chars | CWE-400 |
| Config file | File size | 1 MiB | CWE-400 |
| CA bundle | File size | 10 MiB | CWE-400 |
| Config permissions | Mode check (Unix) | `0600` | CWE-732 |
| Source file | Must be regular file | `is_file()` | CWE-20 |
| Part size | Minimum | >= 5 MiB | CWE-20 |
| Part count | Maximum | <= 10,000 | CWE-400 |
| `--kmac-key` | Hex decode | Fail-fast | CWE-20 |

### Backlog

| Input | Planned | CWE |
|-------|---------|-----|
| Config URL | URL format validation | CWE-20 |
| Config `api` / `path` | Enum validation | CWE-20 |
| Config key lengths | Min/max bounds | CWE-20 |
| Config symlink | `O_NOFOLLOW` | CWE-59 |
| Config TOCTOU | `fstat()` after open | CWE-367 |
| KMAC key min length | Warn if < 32 bytes | CWE-326 |

---

## Output and Error Handling

### Stdout

One JSON result record.  `kmac256` included when `--kmac-key` used;
omitted otherwise.

### Stderr

Structured JSONL audit records.  KMAC key and customization string
are **never** logged.

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Any error |

---

## Audit Logging

### KMAC in audit records

| Field | Record | Present when |
|-------|--------|-------------|
| `kmac_attached` | `put_object_start` | Always (boolean) |
| `kmac256` | `put_object_complete` | Only when `--kmac-key` used |

The KMAC **key** and **customization string** are **never** logged.

---

## Multipart Upload Safety

### KMAC metadata on multipart

`x-amz-meta-kmac256` is attached to `CreateMultipartUpload`.  S3 stores
metadata at the object level, not per-part — the tag is set once and
applies to the completed object.

### Abort on failure

`AbortMultipartUpload` called on any part failure.

---

## File System Safety

### KMAC file access

File is read **twice** when KMAC is enabled: once for the hash (8 KiB
streaming), once for the upload (ByteStream).  Both are streaming — never
fully buffered.

---

## Dependency Supply Chain

### Key dependencies

| Crate | Purpose | Risk notes |
|-------|---------|------------|
| `aws-sdk-s3` | S3 API client | AWS-maintained |
| `rustls` | TLS | Memory-safe |
| `aws-lc-rs` | Crypto provider | FIPS variant available |
| `secrecy` | Credential protection | Well-audited |
| `tiny-keccak` | KMAC256 (SP 800-185) | Pure Rust; ~200 lines; zero deps; CC0-1.0 |
| `base64` | Base64 encoding | Widely used |
| `hex` | Hex decoding | Widely used |
| `mimalloc` | Global allocator (secure) | Widely used |

### Minimum dependency versions

| Crate | Minimum | Advisory |
|-------|---------|----------|
| `aws-lc-sys` | 0.38.0 | CVE-2026-3336/3337/3338 |
| `rustls-webpki` | 0.103.12 | RUSTSEC-2026-0099 |

---

## Known Vulnerabilities and Mitigations

### Application-level findings

| # | CWE | Finding | Severity | Status |
|---|-----|---------|----------|--------|
| 1 | CWE-256, CWE-316 | SecretString zeroing | — | ✅ Remediated |
| 2 | CWE-532, CWE-215 | Debug redaction | — | ✅ Remediated |
| 3 | CWE-732 | Config 0600 check | — | ✅ Remediated |
| 4 | CWE-400 | Timeouts | — | ✅ Remediated |
| 5 | CWE-400 | Config/CA size limits | — | ✅ Remediated |
| 6 | CWE-400 | Part count/size validation | — | ✅ Remediated |
| 7 | CWE-209 | `--verbose` error control | — | ✅ Remediated |
| 8 | CWE-295 | CA bundle additive | — | ✅ Remediated |
| 9 | CWE-778 | Audit records with UUID v7 | — | ✅ Remediated |
| 10 | — | Multipart abort on failure | — | ✅ Remediated |
| 11 | CWE-20 | KMAC key hex validation | — | ✅ Remediated (v0.3.0) |
| 12 | — | KMAC streaming (8 KiB) | — | ✅ Remediated (v0.3.0) |
| 13 | — | KMAC key/custom never logged | — | ✅ Remediated (v0.3.0) |
| 14 | — | Zero cost when unused | — | ✅ Remediated (v0.3.0) |
| 15 | CWE-214 | KMAC key in /proc/PID/cmdline | Low | 🟡 Accepted |
| 16 | CWE-316 | KMAC key String not zeroed | Low | 🟡 Accepted |
| 17 | CWE-326 | No min KMAC key length | Low | 🟡 Backlog |
| 18 | CWE-59 | No symlink validation | Low | 🟡 Backlog |
| 19 | CWE-367 | TOCTOU on config | Low | 🟡 Backlog |
| 20 | CWE-20 | No config schema validation | Low | 🟡 Backlog |
| 21 | — | No content checksum | Medium | 🟠 Planned |
| 22 | — | No per-part retry | Low | 🟡 Planned |

### Dependency-level findings

| # | CVE / Advisory | Crate | Severity | Status |
|---|---------------|-------|----------|--------|
| 1 | CVE-2026-3336 | aws-lc | High | 🟠 Pin >= 0.38.0 |
| 2 | CVE-2026-3338 | aws-lc | High | 🟠 Pin >= 0.38.0 |
| 3 | CVE-2026-3337 | aws-lc | Medium | 🟠 Pin >= 0.38.0 |
| 4 | CVE-2026-4428 | aws-lc | Medium | 🟠 Pin >= 0.38.0 |
| 5 | RUSTSEC-2026-0099 | rustls-webpki | Medium | 🟠 Pin >= 0.103.12 |

---

## Compliance Control Mapping

### NIST SP 800-53 Rev 5

| Control | Title | Implementation |
|---------|-------|----------------|
| AC-3 | Access Enforcement | Config 0600 |
| AU-2 | Event Logging | Start, complete, abort records |
| AU-3 | Audit Content | run_id, alias, bucket, key, size, kmac_attached, kmac256 |
| AU-3(1) | Additional Info | UUID v7 run_id |
| AU-9 | Audit Protection | Operational |
| AU-12 | Audit Generation | JSONL to stderr |
| IA-5(1) | Authenticator Mgmt | SecretString; config 0600 |
| SC-8(1) | Transmission Confidentiality | TLS 1.3 + X25519MLKEM768 |
| SC-12 | Key Management | SecretString lifecycle |
| SC-13 | Crypto Protection | aws-lc-rs; FIPS; KMAC256 (SP 800-185) |
| SI-2 | Flaw Remediation | cargo audit; pinning |
| SI-7 | Integrity | KMAC256 tag on objects |
| SI-10 | Input Validation | Target, config, CA, parts, KMAC hex |
| SI-11 | Error Handling | `--verbose` control |

### ISO 27001:2022

| Control | Implementation |
|---------|----------------|
| A.5.17 | SecretString; config 0600 |
| A.8.3 | Config 0600 |
| A.8.9 | Hardening checklist |
| A.8.15 | JSONL audit |
| A.8.24 | TLS, X25519MLKEM768, FIPS, KMAC256 |
| A.8.28 | Input validation, streaming, error sanitization |

### PCI DSS 4.0

| Req | Implementation |
|-----|----------------|
| 2.2.1 | Hardening checklist |
| 2.2.7 | TLS 1.3 |
| 3.5.1 | SecretString; config 0600 |
| 4.2.1 | TLS 1.2+, X25519MLKEM768 |
| 6.2.4 | Input validation; KMAC256 |
| 6.3.1 | cargo audit; pinning |
| 6.3.2 | SBOM |
| 7.2.2 | Config 0600 |
| 10.2.1 | Audit records |
| 10.2.1.2 | UUID v7 run_id |
| 10.3.2 | Operational |
| 12.3.3 | Documented here |

### DISA STIG

| STIG ID | Implementation |
|---------|----------------|
| V-222425 | Config 0600 |
| V-222457 | Audit records |
| V-222458 | UUID v7 run_id |
| V-222542 | SecretString; KMAC key not logged |
| V-222577 | CA bundle |
| V-222596 | FIPS mode |
| V-222607 | Part size/count, KMAC hex validation |
| V-222609 | Input length validation |
| V-222610 | TLS 1.2 minimum |

### CIS v8.1

| Control | Implementation |
|---------|----------------|
| 3.10 | TLS 1.3, X25519MLKEM768 |
| 3.11 | SecretString; config 0600 |
| 6.1 | Config 0600 |
| 8.2 | Audit records |
| 8.5 | Full metadata including KMAC |
| 16.4 | SBOM |
| 16.6 | Input validation |

---

## Hardening Checklist

### Pre-deployment

- [ ] Config file `0600`: `chmod 600 ~/.mc/config.json`
- [ ] Config owned by service account
- [ ] `cargo audit` clean
- [ ] `cargo deny check` passes
- [ ] `aws-lc-sys` >= 0.38.0
- [ ] `rustls-webpki` >= 0.103.12
- [ ] SBOM generated
- [ ] Binary signed
- [ ] `--verbose` disabled in production
- [ ] Audit pipeline collects stderr
- [ ] Write-once audit storage
- [ ] S3 lifecycle rules expire incomplete multipart uploads

### KMAC256 integrity tagging hygiene

- [ ] KMAC key >= 32 bytes (256 bits)
- [ ] KMAC key NOT hardcoded — use env vars or secrets manager
- [ ] `--kmac-custom` uses unique domain separator per pipeline/tenant
- [ ] KMAC key NOT visible in CI logs (mask in pipeline variables)
- [ ] Verification procedure documented: `mc stat --json | jq .metadata`
- [ ] Key rotation procedure documented
- [ ] Shell history does not persist KMAC key (`HISTCONTROL=ignorespace`)

### Runtime

- [ ] Dedicated least-privilege service account
- [ ] umask `0027` or stricter
- [ ] `HTTPS_PROXY` / `NO_PROXY` configured if needed
- [ ] HMAC keys rotated every 90 days
- [ ] `cargo audit` in CI
- [ ] Audit logs reviewed weekly

### FIPS

- [ ] Built with `--features fips`
- [ ] Go >= 1.22 at build time
- [ ] FIPS module version documented
- [ ] Cipher suites verified

---

## Accepted Risks

| # | Risk | CWE | Justification | Review |
|---|------|-----|---------------|--------|
| 1 | `Credentials::new()` String not zeroed | CWE-316 | Upstream SDK. Short-lived CLI. | 2026-06-09 |
| 2 | Static HMAC keys | CWE-798 | mc config model. Operational. | 2026-06-09 |
| 3 | No symlink validation | CWE-59 | Low risk. Planned. | 2026-06-09 |
| 4 | No TOCTOU hardening | CWE-367 | Low risk. Planned. | 2026-06-09 |
| 5 | Orphaned multipart on SIGKILL | — | Lifecycle rules. | 2026-06-09 |
| 6 | Sequential part uploads | — | Simplifies abort. Parallel planned. | 2026-06-09 |
| 7 | KMAC key in /proc/PID/cmdline | CWE-214 | Short-lived CLI. `--kmac-key-file` planned. | 2026-06-09 |
| 8 | KMAC key String not zeroed | CWE-316 | Short-lived CLI. `SecretString` planned. | 2026-06-09 |
| 9 | No min KMAC key length | CWE-326 | Documented: >= 32 bytes. Warning planned. | 2026-06-09 |

---

## Remediation Roadmap

### Sprint 1 — Immediate

| # | Action | Control | Effort |
|---|--------|---------|--------|
| 1 | Pin `aws-lc-sys >= 0.38.0` | SI-2 | 0.5 h |
| 2 | Pin `rustls-webpki >= 0.103.12` | SI-2 | 0.5 h |
| 3 | `cargo-deny` (`deny.toml`) | SI-2, SR-4 | 1 h |
| 4 | `cargo-cyclonedx` in CI | SA-17, SR-4 | 1 h |
| 5 | `cosign sign-blob` in CI | SI-7 | 2 h |

### Sprint 2 — Short-term

| # | Action | Control | Effort |
|---|--------|---------|--------|
| 6 | `--fips` feature gate | SC-13 | 3 h |
| 7 | Enforce TLS 1.2 minimum | SC-8(1) | 1 h |
| 8 | Config schema validation | SI-10 | 2 h |
| 9 | SHA-256/CRC32C checksum | SI-7 | 3 h |
| 10 | Per-part retry | — | 4 h |
| 11 | `--kmac-key-file` flag | CWE-214 | 2 h |
| 12 | Warn on KMAC key < 32 bytes | CWE-326 | 0.5 h |

### Sprint 3 — Hardening

| # | Action | Control | Effort |
|---|--------|---------|--------|
| 13 | Symlink validation | CWE-59 | 2 h |
| 14 | TOCTOU hardening | CWE-367 | 2 h |
| 15 | `allowed_aliases` policy | AC-3, AC-6 | 2 h |
| 16 | STS / AssumeRole | IA-5(1), SC-12 | 4 h |
| 17 | Warn on stale config | SC-12 | 1 h |
| 18 | Parallel multipart | — | 6 h |
| 19 | `SecretString` for KMAC key | CWE-316 | 2 h |
| 20 | Service account docs | CM-6 | 1 h |

---

## Changelog (security-relevant)

### v0.3.0 (2026-06-09)

- **Added:** Optional KMAC256 integrity tagging via `--kmac-key` and
  `--kmac-custom`.  Uses NIST SP 800-185 KMAC256 with **standard 512-bit
  output** (no truncation, 256-bit security).  Base64-encoded result
  attached as `x-amz-meta-kmac256`.
- **Added:** `tiny-keccak`, `base64`, `hex` dependencies.
- **Added:** `kmac256` in output and audit records.
- **Added:** `kmac_attached` in audit start record.
- **Added:** `mimalloc` (secure mode) as global allocator.
- **Security:** KMAC key hex validation fails fast (SI-10).
- **Security:** File streamed through KMAC in 8 KiB chunks.
- **Security:** KMAC key and customization string never logged.
- **Security:** Zero runtime cost when `--kmac-key` not used.
- **Accepted risks:** KMAC key in cmdline (CWE-214), KMAC key not
  zeroed (CWE-316), no minimum key length (CWE-326).

### v0.2.0

- Clippy-clean. `UploadContext` struct. `div_ceil`/`saturating_sub`.
  `rustfmt`-clean.

### v0.1.0

- Initial release.

---

*This document should be reviewed and updated at least quarterly, or
whenever a new vulnerability is identified or a dependency is updated.*
