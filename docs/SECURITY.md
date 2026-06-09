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
- [KMAC512-384 Integrity Tagging — Security Analysis](#kmac512-384-integrity-tagging--security-analysis)
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

We follow coordinated disclosure.  Please allow us reasonable time to
address the issue before public disclosure.

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
| Object integrity tags | `x-amz-meta-kmac512-384` metadata on uploaded objects |
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
│  │ KMAC512-384 compute    │ │  ← New in v0.3.0
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
| Data integrity attacker | Modify object content after upload | KMAC512-384 tag enables detection — any party with the key can recompute and compare |

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
 3. Compute KMAC512-384 if --kmac-key is set
    a. Stream source file in 8 KiB chunks through Kmac::v512
    b. Finalize to 48 bytes (384 bits)
    c. Base64-encode → 64 characters
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
       - Attach x-amz-meta-kmac512-384 if computed
    b. Multipart: CreateMultipartUpload → UploadPart × N → CompleteMultipartUpload
       - Attach x-amz-meta-kmac512-384 on CreateMultipartUpload
    c. On failure: AbortMultipartUpload + audit abort record
11. Emit result record to stdout (includes kmac512_384 if computed)
12. Emit audit completion record to stderr (includes kmac512_384 if computed)
13. SecretString fields zeroed on drop (CWE-316)
14. Process exits
```

### Data flow

```
Source file ──► KMAC512(key, custom) ──► base64 ──► kmac_b64
                                                       │
Source file ──► ByteStream::from_path() ──► PutObject ─┤
                                            .metadata("kmac512-384", kmac_b64)
                                                       │
Source file ──► ByteStream::read_from() ──► UploadPart × N
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
Audit records ──► stderr (JSONL, includes kmac512_384)
Result record ──► stdout (JSON, includes kmac512_384)
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
                                    SigV4 request signing
                                              │
                                    Drop ──► SecretString::zeroize()
```

### Residual risk

The `Credentials::new()` call in the AWS SDK accepts `String`, not
`SecretString`.  This creates a temporary owned `String` that is **not**
zeroed on drop.  This is an upstream SDK limitation.  In a short-lived CLI
process, the OS reclaims the memory on exit.

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

### Signature scheme

All S3 requests are signed with AWS SigV4 (HMAC-SHA256).

---

## KMAC512-384 Integrity Tagging — Security Analysis

### New in v0.3.0

When `--kmac-key` is provided, `s3-put` computes a KMAC512 (NIST SP 800-185)
hash of the source file, truncated to 384 bits, and attaches the
base64-encoded result as `x-amz-meta-kmac512-384` on the uploaded object.

### Cryptographic properties

| Property | Value |
|----------|-------|
| NIST standard | SP 800-185 (KMAC) |
| Underlying primitive | Keccak-1600 (sponge construction) |
| Classical security | 256-bit (KMAC512) |
| Quantum security (Grover) | ~192-bit (384-bit truncation) |
| Domain separation | Built-in customization parameter (S) per SP 800-185 |
| Output | 384 bits (48 bytes) → 64 base64 characters |
| Construction | `Kmac::v512(key, customization).update(data).finalize(48 bytes)` |

### Implementation details

| Aspect | Detail |
|--------|--------|
| Library | `tiny-keccak` v2.0 with `kmac` feature — pure Rust, ~200 lines |
| Streaming | File read in 8 KiB chunks via `std::io::Read` — never fully buffered |
| Encoding | Base64 (standard alphabet, padded) via `base64` v0.22 |
| Key input | Hex-decoded from CLI `--kmac-key` via `hex` v0.4 |
| Customization | UTF-8 string from `--kmac-custom` (default: empty) |
| Metadata key | `x-amz-meta-kmac512-384` (auto-prefixed by SDK) |

### What the tag proves

| Property | Verified? | Notes |
|----------|-----------|-------|
| **File integrity** | ✅ | Any modification to the file changes the KMAC output |
| **Key authenticity** | ✅ | Only parties holding the key can produce a valid tag |
| **Domain separation** | ✅ | Different `--kmac-custom` values produce different tags for the same file and key |
| **Non-repudiation** | ❌ | KMAC is symmetric — any key holder can produce a tag (not a signature) |
| **Confidentiality** | ❌ | KMAC does not encrypt — the file content is uploaded in cleartext (encrypted in transit by TLS) |

### What the tag does NOT prove

- **Who** computed the tag — any party with the key can produce it
- **When** the tag was computed — no timestamp in the KMAC construction
- **Server-side integrity** — the tag is attached as metadata, not verified by S3; the server stores it but does not validate it

### Metadata persistence

| Operation | Tag preserved? |
|-----------|---------------|
| `CopyObject` with `metadata_directive: COPY` | ✅ Yes |
| `s3-mv` (server-side) | ✅ Yes (uses CopyObject) |
| `CopyObject` with `metadata_directive: REPLACE` | ❌ No (all metadata replaced) |
| Manual metadata update (`mc cp --attr ...` to self) | ❌ No (REPLACE directive) |
| Object versioning | ✅ Each version retains its own metadata |

### Key management considerations

| Concern | Risk | Mitigation |
|---------|------|------------|
| Key on CLI | Visible in `/proc/PID/cmdline` and shell history | Use env vars (`KMAC_KEY=$(cat /path/to/keyfile) s3-put --kmac-key "$KMAC_KEY" ...`); planned: `--kmac-key-file` |
| Key in memory | `String` on heap, not zeroed on drop | Short-lived CLI process; memory reclaimed on exit. Planned: `SecretString` for KMAC key |
| Key rotation | Old tags remain valid with old key | Retain old keys for verification; re-tag objects after rotation if needed |
| Key distribution | Shared secret must reach all verifiers | Use secrets managers (Azure Key Vault, HashiCorp Vault) |
| Empty key | Valid per SP 800-185 but provides no keyed security | Document: use >= 32 bytes (256 bits) |

### Zero-cost when unused

When `--kmac-key` is not provided:

- No KMAC computation occurs
- No `x-amz-meta-kmac512-384` metadata is attached
- `kmac512_384` is omitted from JSON output and audit records
- `kmac_attached: false` in audit start record
- Zero runtime cost — the KMAC code path is not executed
- `tiny-keccak` code is compiled in but never called

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
| `--kmac-key` | Hex-decoded upfront | Fail-fast on invalid hex | CWE-20 |

### Not yet validated (backlog)

| Input | Planned validation | CWE |
|-------|-------------------|-----|
| Config URL field | URL format validation | CWE-20 |
| Config `api` field | Enum validation (`S3v4` / `S3v2`) | CWE-20 |
| Config `path` field | Enum validation (`auto` / `on` / `off`) | CWE-20 |
| Config key lengths | Min/max length bounds | CWE-20 |
| Config file symlink | `O_NOFOLLOW` / `symlink_metadata()` check | CWE-59 |
| Config file TOCTOU | `fstat()` after open | CWE-367 |
| KMAC key minimum length | Warn if < 32 bytes | CWE-326 |

---

## Output and Error Handling

### Stdout

One JSON result record per invocation.  When `--kmac-key` is used,
`kmac512_384` is included.  When not used, the field is omitted.

### Stderr

- Structured JSONL audit records (startup, completion, multipart abort).
- Structured JSON error records on failure.
- CA bundle load warnings.

### Error detail control

| `--verbose` | Behaviour |
|-------------|-----------|
| Off (default) | Error messages contain only the alias name and generic failure descriptions. |
| On | Full diagnostic detail including endpoint URL, bucket, key, upload ID, config path, and known alias list. |

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Any error (config, network, permission, I/O, multipart failure, invalid KMAC key) |

---

## Audit Logging

### Records emitted

| Event | When | Destination |
|-------|------|-------------|
| `put_object_start` | After config load, before API call | stderr |
| `put_object_complete` | After successful upload | stderr |
| `multipart_abort` | When a part upload fails | stderr |
| `ca_bundle_loaded` | When `--ca-bundle` is used | stderr |
| Error record | On any failure | stderr |

### KMAC in audit records

| Field | Record | Present when |
|-------|--------|-------------|
| `kmac_attached` | `put_object_start` | Always (boolean) |
| `kmac512_384` | `put_object_complete` | Only when `--kmac-key` is used |

The KMAC **key** and **customization string** are **never** logged.

### Credentials in audit records

**Never.** Access keys, secret keys, session tokens, and KMAC keys are
never included in any audit record, error message, or stdout output.

### Log integrity

Audit log integrity is an **operational responsibility**.  The consuming
pipeline must enforce write-once semantics or cryptographic log chaining
per NIST SP 800-53 AU-9 and PCI DSS 4.0 Req 10.3.2.

---

## Multipart Upload Safety

### Abort on failure

If any `UploadPart` call fails, the application calls
`AbortMultipartUpload` to clean up.

### KMAC metadata on multipart

The `x-amz-meta-kmac512-384` metadata is attached to the
`CreateMultipartUpload` request.  S3 stores metadata at the object level,
not per-part — so the tag is set once at creation and applies to the
completed object.

### Residual risks

| Risk | Description | Mitigation |
|------|-------------|------------|
| Orphaned uploads on SIGKILL | `AbortMultipartUpload` not called | S3 lifecycle rules |
| No content checksum per part | Parts not verified with SHA-256/CRC32C | Planned |
| No retry on part failure | Single failure aborts entire upload | Planned: per-part retry |

---

## File System Safety

### Source file access

Streamed via `ByteStream::from_path()` (single) or
`ByteStream::read_from().offset().length()` (multipart).

### KMAC file access

Streamed via `std::fs::File` + `std::io::Read` in 8 KiB chunks.  The file
is read **twice** when KMAC is enabled: once for the hash, once for the
upload.  Both reads are streaming — the file is never fully buffered.

---

## Dependency Supply Chain

### Key dependencies

| Crate | Purpose | Risk notes |
|-------|---------|------------|
| `aws-sdk-s3` | S3 API client | AWS-maintained |
| `aws-config` | Credential/region resolution | AWS-maintained |
| `aws-smithy-http-client` | HTTP client builder | AWS-maintained |
| `rustls` | TLS implementation | Memory-safe |
| `aws-lc-rs` | Cryptographic provider | FIPS variant available |
| `secrecy` | Credential memory protection | Well-audited |
| `tiny-keccak` | KMAC512 (SP 800-185) | Pure Rust; ~200 lines; zero deps |
| `base64` | Base64 encoding | Widely used |
| `hex` | Hex decoding | Widely used |
| `mimalloc` | Global allocator (secure mode) | Widely used |
| `clap` | CLI parsing | Widely used |
| `serde` / `serde_json` | Serialization | Widely used |
| `tokio` | Async runtime | Widely used |
| `dirs` | Home directory resolution | Small; portable |
| `uuid` | UUID v7 generation | Widely used |
| `anyhow` | Error handling | Widely used |

### Minimum dependency versions

| Crate | Minimum version | Advisory |
|-------|----------------|----------|
| `aws-lc-sys` | 0.38.0 | CVE-2026-3336, CVE-2026-3337, CVE-2026-3338 |
| `rustls-webpki` | 0.103.12 | RUSTSEC-2026-0099 |

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
| 9 | CWE-778 | Audit records with UUID v7 run_id | — | ✅ Remediated |
| 10 | — | Multipart abort on part failure | — | ✅ Remediated |
| 11 | CWE-20 | KMAC key hex validation fails fast | — | ✅ Remediated (v0.3.0) |
| 12 | — | KMAC file streaming (8 KiB chunks, never buffered) | — | ✅ Remediated (v0.3.0) |
| 13 | — | KMAC key and customization string never logged | — | ✅ Remediated (v0.3.0) |
| 14 | — | Zero runtime cost when --kmac-key not used | — | ✅ Remediated (v0.3.0) |
| 15 | CWE-214 | KMAC key visible in /proc/PID/cmdline | Low | 🟡 Accepted (v0.3.0) |
| 16 | CWE-316 | KMAC key in memory as String (not zeroed on drop) | Low | 🟡 Accepted (v0.3.0) |
| 17 | CWE-326 | No minimum KMAC key length enforced | Low | 🟡 Backlog |
| 18 | CWE-59 | No symlink validation on config or source path | Low | 🟡 Backlog |
| 19 | CWE-367 | TOCTOU on config file and source file | Low | 🟡 Backlog |
| 20 | CWE-20 | No schema validation on config field values | Low | 🟡 Backlog |
| 21 | — | No content checksum (SHA-256/CRC32C) on upload | Medium | 🟠 Planned |
| 22 | — | No per-part retry on multipart failure | Low | 🟡 Planned |

### Dependency-level findings

| # | CVE / Advisory | Crate | Severity | Applicability | Status |
|---|---------------|-------|----------|--------------|--------|
| 1 | CVE-2026-3336 | aws-lc | High | Not reachable | 🟠 Pin aws-lc-sys >= 0.38.0 |
| 2 | CVE-2026-3338 | aws-lc | High | Not reachable | 🟠 Pin aws-lc-sys >= 0.38.0 |
| 3 | CVE-2026-3337 | aws-lc | Medium | Not reachable | 🟠 Pin aws-lc-sys >= 0.38.0 |
| 4 | CVE-2026-4428 | aws-lc | Medium | Relevant if CRL used | 🟠 Pin aws-lc-sys >= 0.38.0 |
| 5 | RUSTSEC-2026-0099 | rustls-webpki | Medium | Relevant with wildcard certs | 🟠 Pin >= 0.103.12 |

---

## Compliance Control Mapping

### NIST SP 800-53 Rev 5

| Control | Title | Implementation |
|---------|-------|----------------|
| AC-3 | Access Enforcement | Config file permission check (0600) |
| AU-2 | Event Logging | Startup, completion, and abort audit records |
| AU-3 | Content of Audit Records | run_id, alias, bucket, key, size, duration, outcome, kmac_attached, kmac512_384 |
| AU-3(1) | Additional Audit Information | UUID v7 run_id for session correlation |
| AU-9 | Protection of Audit Information | Operational — consuming pipeline responsibility |
| AU-12 | Audit Record Generation | All operations emit structured JSONL to stderr |
| IA-5(1) | Authenticator Management | SecretString zeroing; config permission enforcement |
| SC-8(1) | Transmission Confidentiality | TLS 1.3 with X25519MLKEM768 |
| SC-12 | Cryptographic Key Management | SecretString lifecycle; zeroed on drop |
| SC-13 | Cryptographic Protection | aws-lc-rs; optional FIPS mode; KMAC512-384 (SP 800-185) |
| SI-2 | Flaw Remediation | cargo audit in CI; dependency pinning |
| SI-7 | Software/Data Integrity | KMAC512-384 integrity tag on uploaded objects |
| SI-10 | Information Input Validation | Target length, config size, CA size, part size/count, KMAC key hex |
| SI-11 | Error Handling | Verbose mode controls error detail disclosure |

### ISO 27001:2022

| Control | Title | Implementation |
|---------|-------|----------------|
| A.5.17 | Authentication Information | SecretString; config permission check |
| A.8.3 | Information Access Restriction | Config file 0600 |
| A.8.9 | Configuration Management | Documented hardening checklist |
| A.8.15 | Logging | JSONL audit records to stderr |
| A.8.24 | Use of Cryptography | TLS 1.3, X25519MLKEM768, optional FIPS, KMAC512-384 |
| A.8.28 | Secure Coding | Input validation, streaming I/O, error sanitization |

### PCI DSS 4.0

| Requirement | Title | Implementation |
|-------------|-------|----------------|
| 2.2.1 | System Hardening Standards | Documented hardening checklist |
| 2.2.7 | Non-console Admin Access Encryption | TLS 1.3 |
| 3.5.1 | Protect Stored Account Data | SecretString; config 0600 |
| 4.2.1 | Strong Cryptography for Transmission | TLS 1.2+, X25519MLKEM768 |
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
| V-222542 | Protect Authenticator Integrity | SecretString zeroing; KMAC key not logged |
| V-222577 | DoD-Approved PKI Certificates | CA bundle support |
| V-222596 | NSA-Approved Cryptography | Optional FIPS mode |
| V-222607 | Validate All Input | Part size/count, config size, KMAC key hex |
| V-222609 | Restrict Overly Long Input | Input length validation |
| V-222610 | Enforce TLS 1.2 Minimum | rustls default; documented |

### CIS Controls v8.1

| Control | Title | Implementation |
|---------|-------|----------------|
| 3.10 | Encrypt Sensitive Data in Transit | TLS 1.3, X25519MLKEM768 |
| 3.11 | Encrypt Sensitive Data at Rest | SecretString; config 0600 |
| 6.1 | Establish Access Granting Process | Config permission enforcement |
| 8.2 | Collect Audit Logs | JSONL audit records to stderr |
| 8.5 | Collect Detailed Audit Logs | Full metadata including KMAC indicator |
| 16.4 | Third-Party Software Inventory | SBOM via cargo-cyclonedx |
| 16.6 | Secure Coding Practices | Input validation, error handling |

---

## Hardening Checklist

### Pre-deployment

- [ ] Config file permissions are `0600`: `chmod 600 ~/.mc/config.json`
- [ ] Config file is owned by the service account running `s3-put`
- [ ] `cargo audit` reports no unresolved advisories
- [ ] `cargo deny check` passes
- [ ] `aws-lc-sys` >= 0.38.0 in `Cargo.lock`
- [ ] `rustls-webpki` >= 0.103.12 in `Cargo.lock`
- [ ] SBOM generated and archived
- [ ] Release binary signed
- [ ] `--verbose` is **not** enabled in production
- [ ] Audit log pipeline collects stderr
- [ ] Audit log storage enforces write-once / append-only
- [ ] S3 bucket lifecycle rules expire incomplete multipart uploads

### KMAC integrity tagging hygiene

- [ ] KMAC key is >= 32 bytes (256 bits)
- [ ] KMAC key is NOT hardcoded in scripts — use env vars or secrets manager
- [ ] `--kmac-custom` uses a unique domain separator per pipeline/tenant
- [ ] KMAC key is NOT visible in CI logs (mask in pipeline variables)
- [ ] Verification procedure documented: `mc stat --json | jq .metadata`
- [ ] Key rotation procedure documented: retain old keys for verification
- [ ] Shell history does not persist KMAC key (`HISTCONTROL=ignorespace`)

### Runtime

- [ ] Process runs under a dedicated, least-privilege service account
- [ ] Process umask is set to `0027` or stricter
- [ ] `HTTPS_PROXY` / `NO_PROXY` configured if needed
- [ ] HMAC keys rotated at least every 90 days
- [ ] `cargo audit` run in CI on every build
- [ ] Audit logs reviewed at least weekly

### FIPS environments

- [ ] Built with `--features fips`
- [ ] Go toolchain >= 1.22 at build time
- [ ] FIPS module version documented
- [ ] Cipher suites verified

---

## Accepted Risks

| # | Risk | CWE | Justification | Review date |
|---|------|-----|---------------|-------------|
| 1 | `Credentials::new()` accepts `String` (not zeroed) | CWE-316 | Upstream SDK limitation. Short-lived CLI. | 2026-06-09 |
| 2 | Static HMAC keys with no rotation enforcement | CWE-798 | Inherits mc config model. Operational responsibility. | 2026-06-09 |
| 3 | No symlink validation on config or source path | CWE-59 | Low risk for CLI under service account. Planned. | 2026-06-09 |
| 4 | No TOCTOU hardening on config file | CWE-367 | Low risk for short-lived CLI. Planned. | 2026-06-09 |
| 5 | Orphaned multipart uploads on SIGKILL | — | S3 lifecycle rules. AbortMultipartUpload on caught errors. | 2026-06-09 |
| 6 | Sequential part uploads | — | Simplifies abort logic. Parallel planned. | 2026-06-09 |
| 7 | KMAC key visible in /proc/PID/cmdline | CWE-214 | Short-lived CLI. Planned: `--kmac-key-file`. Use env vars in production. | 2026-06-09 |
| 8 | KMAC key in memory as String (not zeroed) | CWE-316 | Short-lived CLI. Planned: `SecretString` for KMAC key. | 2026-06-09 |
| 9 | No minimum KMAC key length enforced | CWE-326 | Documented: use >= 32 bytes. Planned: warning on short keys. | 2026-06-09 |

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
| 8 | Add config schema validation | SI-10 | 2 h |
| 9 | Add SHA-256 / CRC32C content checksum on upload | SI-7 | 3 h |
| 10 | Add per-part retry with exponential backoff | — | 4 h |
| 11 | Add `--kmac-key-file` flag (read key from file) | CWE-214 | 2 h |
| 12 | Warn on KMAC key < 32 bytes | CWE-326 | 0.5 h |

### Sprint 3 — Hardening (defense-in-depth)

| # | Action | CWE / Control | Effort |
|---|--------|---------------|--------|
| 13 | Symlink validation on config and source paths | CWE-59 | 2 h |
| 14 | TOCTOU hardening with `O_NOFOLLOW` + `fstat()` | CWE-367 | 2 h |
| 15 | Add `allowed_aliases` policy file | AC-3, AC-6 | 2 h |
| 16 | Add STS / AssumeRole credential support | IA-5(1), SC-12 | 4 h |
| 17 | Warn on stale config file (> 90 days) | SC-12 | 1 h |
| 18 | Parallel multipart upload with bounded concurrency | — | 6 h |
| 19 | Use `SecretString` for KMAC key in memory | CWE-316 | 2 h |
| 20 | Document recommended service account setup | CM-6 | 1 h |

---

## Changelog (security-relevant)

### v0.3.0 (2026-06-09)

- **Added:** Optional KMAC512-384 integrity tagging via `--kmac-key` and
  `--kmac-custom`.
- **Added:** `tiny-keccak`, `base64`, `hex` dependencies.
- **Added:** `kmac512_384` in output and audit records.
- **Added:** `kmac_attached` in audit start record.
- **Added:** KMAC512-384 Security Analysis section in SECURITY.md.
- **Added:** KMAC key management guidance and hardening checklist items.
- **Added:** `mimalloc` (secure mode) as global allocator.
- **Security:** KMAC key hex validation fails fast (SI-10).
- **Security:** File streamed through KMAC in 8 KiB chunks.
- **Security:** KMAC key and customization string never logged.
- **Security:** Zero runtime cost when `--kmac-key` not used.
- **Accepted risks:** KMAC key visible in cmdline (CWE-214), KMAC key
  not zeroed in memory (CWE-316), no minimum key length (CWE-326).

### v0.2.0

- Clippy-clean pass.
- `UploadContext` struct.
- `div_ceil` and `saturating_sub` fixes.
- `rustfmt`-clean pass.

### v0.1.0

- Initial release.

---

*This document should be reviewed and updated at least quarterly, or
whenever a new vulnerability is identified or a dependency is updated.*
