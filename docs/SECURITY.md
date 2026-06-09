# Security Policy — s3-put

> **Version:** 0.2.0
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
| 0.2.x   | Active   | Yes              |
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

We follow coordinated disclosure.  Please allow us reasonable time to
address the issue before public disclosure.

---

## Threat Model

### Assets protected

| Asset | Description |
|-------|-------------|
| HMAC credentials | `accessKey` / `secretKey` in `~/.mc/config.json` |
| Data in transit | File content between local filesystem and S3 endpoint |
| Data at rest (source) | Local files read by the application |
| Data at rest (remote) | Objects written to S3 buckets |
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
| Local unprivileged user | Read config file, inspect process memory | Config permission check (0600), SecretString zeroing |
| Network observer (passive) | Capture TLS traffic for later decryption | X25519MLKEM768 PQ KX, TLS 1.3 |
| Network attacker (active) | MITM, certificate substitution, response injection | CA bundle validation, certificate chain verification |
| Malicious endpoint | Return crafted responses, manipulate ETags | ETag validation in multipart completion, abort on failure |
| Supply chain attacker | Compromise a dependency crate | cargo audit, SBOM, dependency pinning |
| Insider with bucket access | Read uploaded objects, enumerate keys | Out of scope — access control is an S3 policy responsibility |

---

## Security Architecture

### Process lifecycle

```
 1. Parse CLI arguments
 2. Validate input lengths (SI-10)
    a. Target string length (2,048 chars max)
    b. Part size minimum (5 MiB)
    c. Part count maximum (10,000)
 3. Validate source file
    a. Must exist and be a regular file
    b. Multipart constraint pre-check
 4. Load ~/.mc/config.json
    a. Check file permissions (CWE-732)
    b. Enforce file size limit (CWE-400)
    c. Parse JSON → McConfig with SecretString fields
 5. Resolve alias, bucket, key
    a. Key derivation from source filename if target ends with '/'
    b. Sanitize error messages (CWE-209)
 6. Build HTTPS client
    a. rustls + aws-lc-rs with prefer-post-quantum
    b. Optional CA bundle (additive, not replacing)
 7. Build S3 client with timeout config
 8. Emit audit start record to stderr (CWE-778)
 9. Upload
    a. Single PutObject (file <= threshold)
    b. Multipart: CreateMultipartUpload → UploadPart × N → CompleteMultipartUpload
    c. On failure: AbortMultipartUpload + audit abort record
10. Emit result record to stdout
11. Emit audit completion record to stderr
12. SecretString fields zeroed on drop (CWE-316)
13. Process exits
```

### Data flow

```
Source file ──► ByteStream::from_path() ──────────────────────► PutObject
                                                                    │
Source file ──► ByteStream::read_from().offset().length() ──► UploadPart × N
                                                                    │
                            SigV4 signing ◄── Credentials ◄── SecretString
                                   │
                                   ▼
                    TLS 1.3 (X25519MLKEM768) ──► S3 endpoint
                                                      │
                                                      ▼
                                              ETag / Upload ID
                                                      │
                                                      ▼
Audit records ──► stderr (JSONL)
Result record ──► stdout (JSON)
```

### Single-part vs multipart decision

```
file_size <= multipart_threshold_mib ?
    ├── YES → PutObject (single API call)
    └── NO  → CreateMultipartUpload
              ├── UploadPart × ceil(file_size / part_size)
              ├── CompleteMultipartUpload (on success)
              └── AbortMultipartUpload (on any part failure)
```

---

## Credential Protection

### Storage

| Layer | Control | CWE |
|-------|---------|-----|
| Config file | `~/.mc/config.json` must be mode `0600` on Unix; application refuses to start if group/other bits are set | CWE-732 |
| In-memory | `accessKey` and `secretKey` deserialized into `secrecy::SecretString` which zeroes memory on drop via `zeroize` | CWE-256, CWE-316 |
| Debug output | `SecretString` implements `Debug` as `[REDACTED]` — credentials never appear in panic backtraces, log output, or error chains | CWE-532, CWE-215 |
| Error messages | Alias lists, endpoint URLs, and config paths are hidden unless `--verbose` is explicitly set | CWE-209 |

### Credential lifecycle

```
config.json ──► serde_json::from_str ──► McAlias.access_key: SecretString
                                         McAlias.secret_key: SecretString
                                              │
                                    expose_secret().to_string()
                                              │
                                    Credentials::new(access_key, secret_key, ...)
                                              │
                                    SigV4 request signing (PutObject / UploadPart)
                                              │
                                    Drop ──► SecretString::zeroize()
```

### Residual risk

The `Credentials::new()` call in the AWS SDK accepts `String`, not
`SecretString`.  This creates a temporary owned `String` that is **not**
zeroed on drop.  This is an upstream SDK limitation.  In a short-lived CLI
process, the OS reclaims the memory on exit.  For long-running services,
consider explicit `zeroize` of the `Credentials` struct.

---

## Cryptographic Controls

### TLS configuration

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| TLS library | rustls 0.23.x | Memory-safe, no OpenSSL dependency |
| Crypto provider | aws-lc-rs (aws-lc) | NIST-validated algorithms, PQ support |
| Preferred KX | X25519MLKEM768 (hybrid ML-KEM-768 + X25519) | Protect against collect-now-harvest-later |
| Fallback KX | X25519, secp256r1, secp384r1 | Compatibility with endpoints that don't support PQ |
| Minimum TLS version | 1.2 (rustls default) | PCI DSS 4.0 Req 4.2.1 |
| Certificate validation | Platform-native roots + optional PEM CA bundle | CWE-295 |
| FIPS mode | Optional (`--features fips` build) | NIST SP 800-53 SC-13 |

### Post-quantum key exchange

The `prefer-post-quantum` feature on `rustls` places X25519MLKEM768
(group `0x6399`) first in the TLS 1.3 ClientHello `supported_groups`
extension.  If the server does not support it, negotiation falls back
automatically.  No application code changes are required.

### Signature scheme

All S3 requests are signed with AWS SigV4 (HMAC-SHA256).  The signing
is performed by the AWS SDK's `aws-sigv4` crate.  This applies to:

- `PutObject` requests (single-part upload)
- `CreateMultipartUpload` requests
- `UploadPart` requests (each part individually signed)
- `CompleteMultipartUpload` requests
- `AbortMultipartUpload` requests

---

## Input Validation

| Input | Validation | Limit | CWE |
|-------|-----------|-------|-----|
| Target string (`alias/bucket[/key]`) | Maximum length check | 2,048 characters | CWE-400 |
| Config file (`~/.mc/config.json`) | File size check before read | 1 MiB | CWE-400 |
| CA bundle (`--ca-bundle`) | File size check before read | 10 MiB | CWE-400 |
| Config file permissions | Mode check on Unix | `0600` required | CWE-732 |
| Source file | Must exist and be a regular file | `is_file()` check | CWE-20 |
| Part size (`--part-size-mib`) | Minimum size enforcement | >= 5 MiB (S3 spec) | CWE-20 |
| Part count | Pre-upload validation | <= 10,000 (S3 spec) | CWE-400 |
| Target parsing | Must contain alias + bucket (2+ segments) | Non-empty | CWE-20 |
| Key resolution | Filename derived from source if target key is empty or ends with `/` | — | CWE-20 |

### Not yet validated (backlog)

| Input | Planned validation | CWE |
|-------|-------------------|-----|
| Config URL field | URL format validation | CWE-20 |
| Config `api` field | Enum validation (`S3v4` / `S3v2`) | CWE-20 |
| Config `path` field | Enum validation (`auto` / `on` / `off`) | CWE-20 |
| Config key lengths | Min/max length bounds | CWE-20 |
| Config file symlink | `O_NOFOLLOW` / `symlink_metadata()` check | CWE-59 |
| Config file TOCTOU | `fstat()` after open | CWE-367 |

---

## Output and Error Handling

### Stdout

One JSON result record per invocation containing: status, source, bucket,
key, size, etag, content_type, upload_method, parts (if multipart), and
duration_ms.

### Stderr

- Structured JSONL audit records (startup, completion, multipart abort).
- Structured JSON error records on failure.
- CA bundle load warnings.

### Error detail control

| `--verbose` | Behaviour |
|-------------|-----------|
| Off (default) | Error messages contain only the alias name and generic failure descriptions. Endpoint URLs, bucket names, key names, upload IDs, and alias lists are **not** disclosed. |
| On | Full diagnostic detail including endpoint URL, bucket, key, upload ID, config path, and known alias list. Intended for operator troubleshooting only. |

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Any error (config, network, permission, I/O, multipart failure) |

---

## Audit Logging

### Records emitted

| Event | When | Destination |
|-------|------|-------------|
| `put_object_start` | After config load, before API call | stderr |
| `put_object_complete` | After successful upload | stderr |
| `multipart_abort` | When a part upload fails and AbortMultipartUpload is called | stderr |
| `ca_bundle_loaded` | When `--ca-bundle` is used | stderr |
| Error record | On any failure | stderr |

### Correlation

All records within a single invocation share a `run_id` (UUID v7,
timestamp-ordered) for log correlation.

### Fields included in audit records

| Field | Start | Complete | Abort | Rationale |
|-------|-------|----------|-------|-----------|
| `event` | ✓ | ✓ | ✓ | Event type identification |
| `run_id` | ✓ | ✓ | — | Session correlation (AU-3(1)) |
| `alias` | ✓ | ✓ | — | Identity of credential set used |
| `endpoint` | ✓ | — | — | Target service identification |
| `bucket` | ✓ | ✓ | ✓ | Resource accessed |
| `key` | ✓ | ✓ | ✓ | Object written |
| `source` | ✓ | — | — | Local file path |
| `file_size` | ✓ | — | — | Pre-upload size |
| `upload_method` | ✓ | ✓ | — | `single` or `multipart` |
| `content_type` | ✓ | — | — | MIME type used |
| `region` | ✓ | — | — | Service region |
| `path_style` | ✓ | — | — | Addressing mode |
| `pq_kx` | ✓ | — | — | Key exchange algorithm offered |
| `ca_bundle` | ✓ | — | — | Custom trust store indicator |
| `size` | — | ✓ | — | Bytes uploaded |
| `etag` | — | ✓ | — | Server-returned integrity tag |
| `parts` | — | ✓ | — | Part count (multipart only) |
| `duration_ms` | — | ✓ | — | Operation timing |
| `outcome` | — | ✓ | — | Success/failure |
| `upload_id` | — | — | ✓ | Multipart upload identifier |

### Credentials in audit records

**Never.** Access keys, secret keys, and session tokens are never included
in any audit record, error message, or stdout output.

### Log integrity

Audit log integrity is an **operational responsibility**.  This application
emits structured records; the consuming pipeline must enforce:

- Write-once semantics (e.g., append-only storage)
- Cryptographic log chaining or HMAC signing
- Centralized collection with tamper detection

Per NIST SP 800-53 AU-9 and PCI DSS 4.0 Req 10.3.2.

---

## Multipart Upload Safety

### Abort on failure

If any `UploadPart` call fails, the application:

1. Emits a `multipart_abort` audit record to stderr with the `upload_id`,
   `bucket`, and `key`.
2. Calls `AbortMultipartUpload` to clean up the incomplete upload on the
   server.
3. Returns a contextual error to the caller.

This prevents **orphaned multipart uploads** from consuming storage quota
and potentially leaking partial data.

### Part integrity

Each `UploadPart` response includes an ETag.  The application collects
all part ETags and submits them in the `CompleteMultipartUpload` request.
The server validates that:

- All declared parts are present.
- Part numbers are sequential and 1-based.
- ETags match the uploaded content.

### Sequential upload

Parts are uploaded **sequentially**, not in parallel.  This simplifies
error handling and abort logic.  Parallel upload is planned for a future
release with per-part retry and bounded concurrency.

### Upload ID exposure

The `upload_id` is emitted **only** in the `multipart_abort` audit record
on stderr.  It is never included in stdout output.  In `--verbose` mode,
it may appear in error messages for diagnostic purposes.

### Residual risks

| Risk | Description | Mitigation |
|------|-------------|------------|
| Orphaned uploads on process kill | If the process is killed (SIGKILL) during multipart upload, `AbortMultipartUpload` is not called | Configure S3 lifecycle rules to expire incomplete multipart uploads after N days |
| No content checksum | Parts are not verified with SHA-256 / CRC32C | Planned for future release |
| No retry on part failure | A single part failure aborts the entire upload | Planned: per-part retry with exponential backoff |

---

## File System Safety

### Source file access

The application reads the source file via `ByteStream::from_path()` (single
upload) or `ByteStream::read_from().offset().length()` (multipart).  Both
methods stream from disk without buffering the entire file in memory.

### Content-type detection

Content-type is auto-detected from the file extension using a static mapping
of common MIME types.  The `--content-type` flag overrides auto-detection.
The extension-based mapping does not execute or inspect file contents.

### Residual risks

| Risk | CWE | Mitigation status |
|------|-----|-------------------|
| Symlink following on source file | CWE-59 | Not yet mitigated — source file symlinks are followed |
| Symlink following on config file | CWE-59 | Not yet mitigated — planned |
| TOCTOU between source stat and upload | CWE-367 | Low risk — source is read after stat; content change mid-upload would be detected by S3 ETag mismatch |

---

## Dependency Supply Chain

### Key dependencies

| Crate | Purpose | Risk notes |
|-------|---------|------------|
| `aws-sdk-s3` | S3 API client (PutObject, multipart) | AWS-maintained; high scrutiny |
| `aws-config` | Credential/region resolution | AWS-maintained |
| `aws-smithy-http-client` | HTTP client builder | AWS-maintained |
| `rustls` | TLS implementation | Memory-safe; no C code |
| `aws-lc-rs` | Cryptographic provider | Wraps aws-lc (C); FIPS-validated variant available |
| `secrecy` | Credential memory protection | Small, focused crate; well-audited |
| `clap` | CLI argument parsing | Widely used; low risk |
| `serde` / `serde_json` | Serialization | Widely used; low risk |
| `tokio` | Async runtime | Widely used; high scrutiny |
| `dirs` | Home directory resolution | Small; portable |
| `uuid` | UUID v7 generation | Widely used; low risk |
| `anyhow` | Error handling | Widely used; low risk |

### Required actions

| Action | Tool | Frequency |
|--------|------|-----------|
| Vulnerability scanning | `cargo audit` | Every build (CI) |
| License compliance | `cargo deny check licenses` | Every build (CI) |
| SBOM generation | `cargo cyclonedx --format json` | Every release |
| Binary signing | `cosign sign-blob` | Every release |
| Dependency tree review | `cargo tree --duplicates` | Monthly |

### Minimum dependency versions

The following minimum versions must be enforced in `Cargo.lock` to
address known CVEs:

| Crate | Minimum version | Advisory |
|-------|----------------|----------|
| `aws-lc-sys` | 0.38.0 | CVE-2026-3336, CVE-2026-3337, CVE-2026-3338 |
| `rustls-webpki` | 0.103.12 | RUSTSEC-2026-0099 |

Add to CI:

```bash
cargo audit
cargo deny check advisories
```

---

## Known Vulnerabilities and Mitigations

### Application-level findings

| # | CWE | Finding | Severity | Status |
|---|-----|---------|----------|--------|
| 1 | CWE-256, CWE-316 | Credentials stored as SecretString, zeroed on drop | — | ✅ Remediated |
| 2 | CWE-532, CWE-215 | Debug trait redacts credentials via SecretString | — | ✅ Remediated |
| 3 | CWE-732 | Config file permission check enforces 0600 | — | ✅ Remediated |
| 4 | CWE-400 | Timeouts configured (10s/300s/120s) | — | ✅ Remediated |
| 5 | CWE-400 | Config and CA bundle file size limits | — | ✅ Remediated |
| 6 | CWE-400 | Part count and part size validation | — | ✅ Remediated |
| 7 | CWE-209 | Error detail controlled by --verbose | — | ✅ Remediated |
| 8 | CWE-295 | CA bundle adds to (not replaces) native roots | — | ✅ Remediated |
| 9 | CWE-778 | Audit records with UUID v7 run_id (start, complete, abort) | — | ✅ Remediated |
| 10 | — | Multipart abort on part failure prevents orphaned uploads | — | ✅ Remediated |
| 11 | CWE-59 | No symlink validation on config or source path | Low | 🟡 Backlog |
| 12 | CWE-367 | TOCTOU on config file and source file | Low | 🟡 Backlog |
| 13 | CWE-20 | No schema validation on config field values | Low | 🟡 Backlog |
| 14 | — | No content checksum (SHA-256/CRC32C) on upload | Medium | 🟠 Planned |
| 15 | — | No per-part retry on multipart failure | Low | 🟡 Planned |
| 16 | — | Orphaned uploads possible on SIGKILL | Low | 🟡 Operational (lifecycle rules) |

### Dependency-level findings

| # | CVE / Advisory | Crate | Severity | Applicability | Status |
|---|---------------|-------|----------|--------------|--------|
| 1 | CVE-2026-3336 | aws-lc | High | Not reachable (PKCS7_verify) | 🟠 Pin aws-lc-sys >= 0.38.0 |
| 2 | CVE-2026-3338 | aws-lc | High | Not reachable (PKCS7_verify) | 🟠 Pin aws-lc-sys >= 0.38.0 |
| 3 | CVE-2026-3337 | aws-lc | Medium | Not reachable (AES-CCM) | 🟠 Pin aws-lc-sys >= 0.38.0 |
| 4 | CVE-2026-4428 | aws-lc | Medium | Relevant if CRL revocation is used | 🟠 Pin aws-lc-sys >= 0.38.0 |
| 5 | RUSTSEC-2026-0099 | rustls-webpki | Medium | Relevant with name-constrained wildcard certs | 🟠 Pin rustls-webpki >= 0.103.12 |

---

## Compliance Control Mapping

### NIST SP 800-53 Rev 5

| Control | Title | Implementation |
|---------|-------|----------------|
| AC-3 | Access Enforcement | Config file permission check (0600) |
| AU-2 | Event Logging | Startup, completion, and abort audit records |
| AU-3 | Content of Audit Records | run_id, alias, bucket, key, size, duration, outcome, upload_id |
| AU-3(1) | Additional Audit Information | UUID v7 run_id for session correlation |
| AU-9 | Protection of Audit Information | Operational — consuming pipeline responsibility |
| AU-12 | Audit Record Generation | All operations emit structured JSONL to stderr |
| IA-5(1) | Authenticator Management | SecretString zeroing; config permission enforcement |
| SC-8(1) | Transmission Confidentiality | TLS 1.3 with X25519MLKEM768 |
| SC-12 | Cryptographic Key Management | SecretString lifecycle; zeroed on drop |
| SC-13 | Cryptographic Protection | aws-lc-rs; optional FIPS mode |
| SI-2 | Flaw Remediation | cargo audit in CI; dependency pinning |
| SI-10 | Information Input Validation | Target length, config size, CA size, part size/count |
| SI-11 | Error Handling | Verbose mode controls error detail disclosure |

### ISO 27001:2022

| Control | Title | Implementation |
|---------|-------|----------------|
| A.5.17 | Authentication Information | SecretString; config permission check |
| A.8.3 | Information Access Restriction | Config file 0600 |
| A.8.9 | Configuration Management | Documented hardening checklist |
| A.8.15 | Logging | JSONL audit records to stderr |
| A.8.24 | Use of Cryptography | TLS 1.3, X25519MLKEM768, optional FIPS |
| A.8.28 | Secure Coding | Input validation, streaming I/O, error sanitization |

### PCI DSS 4.0

| Requirement | Title | Implementation |
|-------------|-------|----------------|
| 2.2.1 | System Hardening Standards | Documented hardening checklist |
| 2.2.7 | Non-console Admin Access Encryption | TLS 1.3 for all S3 communications |
| 3.5.1 | Protect Stored Account Data | SecretString; config 0600 |
| 4.2.1 | Strong Cryptography for Transmission | TLS 1.2+, X25519MLKEM768 preferred |
| 6.2.4 | Software Attack Prevention | Input validation, error sanitization |
| 6.3.1 | Vulnerability Management | cargo audit; dependency pinning |
| 6.3.2 | Software Inventory | SBOM via cargo-cyclonedx |
| 7.2.2 | Access Based on Job Function | Config file permission enforcement |
| 10.2.1 | Audit Log Capture | Startup, completion, and abort records |
| 10.2.1.2 | Unique Event Identification | UUID v7 run_id |
| 10.3.2 | Audit Log Protection | Operational — pipeline responsibility |
| 12.3.3 | Cipher Suite Documentation | Documented in this file |

### DISA STIG (Application Security)

| STIG ID | Title | Implementation |
|---------|-------|----------------|
| V-222425 | Enforce Approved Authorizations | Config permission check |
| V-222457 | Generate Audit Records | JSONL audit records |
| V-222458 | Session-Level Audit | UUID v7 run_id |
| V-222542 | Protect Authenticator Integrity | SecretString zeroing |
| V-222577 | DoD-Approved PKI Certificates | CA bundle support; platform-native roots |
| V-222596 | NSA-Approved Cryptography | Optional FIPS mode |
| V-222607 | Validate All Input | Part size/count, config size, target length |
| V-222609 | Restrict Overly Long Input | Input length validation |
| V-222610 | Enforce TLS 1.2 Minimum | rustls default; documented |

### CIS Controls v8.1

| Control | Title | Implementation |
|---------|-------|----------------|
| 3.10 | Encrypt Sensitive Data in Transit | TLS 1.3, X25519MLKEM768 |
| 3.11 | Encrypt Sensitive Data at Rest | SecretString; config 0600 |
| 6.1 | Establish Access Granting Process | Config permission enforcement |
| 8.2 | Collect Audit Logs | JSONL audit records to stderr |
| 8.5 | Collect Detailed Audit Logs | Full metadata in audit records |
| 16.4 | Third-Party Software Inventory | SBOM via cargo-cyclonedx |
| 16.6 | Secure Coding Practices | Input validation, error handling |

---

## Hardening Checklist

### Pre-deployment

- [ ] Config file permissions are `0600`: `chmod 600 ~/.mc/config.json`
- [ ] Config file is owned by the service account running `s3-put`
- [ ] `cargo audit` reports no unresolved advisories
- [ ] `aws-lc-sys` >= 0.38.0 in `Cargo.lock`
- [ ] `rustls-webpki` >= 0.103.12 in `Cargo.lock`
- [ ] SBOM generated and archived: `cargo cyclonedx --format json`
- [ ] Release binary signed: `cosign sign-blob`
- [ ] `--verbose` is **not** enabled in production automation scripts
- [ ] Audit log pipeline is configured to collect stderr output
- [ ] Audit log storage enforces write-once / append-only semantics
- [ ] S3 bucket lifecycle rules expire incomplete multipart uploads

### Runtime

- [ ] Process runs under a dedicated, least-privilege service account
- [ ] Process umask is set to `0027` or stricter
- [ ] `HTTPS_PROXY` / `NO_PROXY` configured if network requires proxy
- [ ] Source files are read from a directory with appropriate ACLs
- [ ] HMAC keys are rotated at least every 90 days
- [ ] `cargo audit` is run in CI on every build
- [ ] Audit logs are reviewed at least weekly

### FIPS environments

- [ ] Built with `--features fips`
- [ ] Go toolchain >= 1.22 available at build time
- [ ] FIPS module version documented in deployment records
- [ ] Cipher suites verified against approved list

### Multipart upload hygiene

- [ ] S3 bucket lifecycle rule: abort incomplete multipart uploads after 7 days
- [ ] Monitor for orphaned multipart uploads via `ListMultipartUploads`
- [ ] Alert on `multipart_abort` audit events in SIEM

---

## Accepted Risks

| # | Risk | CWE | Justification | Review date |
|---|------|-----|---------------|-------------|
| 1 | `Credentials::new()` accepts `String` (not zeroed on drop) | CWE-316 | Upstream AWS SDK limitation. Short-lived CLI process; memory reclaimed on exit. Acceptable for CLI use; revisit if adapted to long-running service. | 2026-06-09 |
| 2 | Static HMAC keys with no rotation enforcement | CWE-798 | Inherits MinIO Client config model. Documented as known limitation. Key rotation is an operational responsibility. | 2026-06-09 |
| 3 | No symlink validation on config or source path | CWE-59 | Low risk for interactive CLI use under a dedicated service account. Planned for future hardening sprint. | 2026-06-09 |
| 4 | No TOCTOU hardening on config file | CWE-367 | Low risk for short-lived CLI process. Planned for service-mode adaptation. | 2026-06-09 |
| 5 | Orphaned multipart uploads on SIGKILL | — | Mitigated operationally via S3 lifecycle rules. Application calls AbortMultipartUpload on all caught errors. | 2026-06-09 |
| 6 | Sequential part uploads (no parallelism) | — | Simplifies error handling and abort logic. Parallel upload planned for future release. Acceptable for current PoC/engineering use. | 2026-06-09 |

---

## Remediation Roadmap

### Sprint 1 — Immediate (blocks audit)

| # | Action | CWE / Control | Effort |
|---|--------|---------------|--------|
| 1 | Pin `aws-lc-sys >= 0.38.0` in Cargo.lock | SI-2 | 0.5 h |
| 2 | Pin `rustls-webpki >= 0.103.12` in Cargo.lock | SI-2 | 0.5 h |
| 3 | Add `cargo-deny` configuration (`deny.toml`) | SI-2, SR-4 | 1 h |
| 4 | Add `cargo-cyclonedx` to CI pipeline | SA-17, SR-4 | 1 h |
| 5 | Add `cosign sign-blob` to release pipeline | SI-7 | 2 h |

### Sprint 2 — Short-term (compliance readiness)

| # | Action | CWE / Control | Effort |
|---|--------|---------------|--------|
| 6 | Add `--fips` feature gate | SC-13 | 3 h |
| 7 | Enforce TLS 1.2 minimum explicitly | SC-8(1) | 1 h |
| 8 | Add config schema validation (URL, api, path, key lengths) | SI-10 | 2 h |
| 9 | Add SHA-256 / CRC32C content checksum on upload | SI-7 | 3 h |
| 10 | Add per-part retry with exponential backoff | — | 4 h |

### Sprint 3 — Hardening (defense-in-depth)

| # | Action | CWE / Control | Effort |
|---|--------|---------------|--------|
| 11 | Symlink validation on config and source paths | CWE-59 | 2 h |
| 12 | TOCTOU hardening with `O_NOFOLLOW` + `fstat()` | CWE-367 | 2 h |
| 13 | Add `allowed_aliases` policy file | AC-3, AC-6 | 2 h |
| 14 | Add STS / AssumeRole credential support | IA-5(1), SC-12 | 4 h |
| 15 | Warn on stale config file (> 90 days) | SC-12 | 1 h |
| 16 | Parallel multipart upload with bounded concurrency | — | 6 h |
| 17 | Document recommended umask and service account setup | CM-6 | 1 h |

---

*This document should be reviewed and updated at least quarterly, or
whenever a new vulnerability is identified or a dependency is updated.*
