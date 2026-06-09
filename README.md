# s3-put

> **MinIO-compatible S3 file uploader with structured JSONL output, optional KMAC512-384 integrity tagging, and post-quantum TLS.**

`s3-put` is a Rust CLI tool that reads `~/.mc/config.json` (MinIO Client
configuration) and performs the equivalent of:

```bash
mc put <filepath> <alias>/<bucket>[/<key>]
```

It emits a JSON result record to **stdout** and structured audit records to
**stderr**, making it suitable for automation pipelines, SIEM ingestion, and
compliance-auditable environments.

---

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Build](#build)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Key Resolution](#key-resolution)
- [Upload Strategy](#upload-strategy)
- [KMAC512-384 Integrity Tagging](#kmac512-384-integrity-tagging)
- [Output Schema](#output-schema)
- [TLS and Post-Quantum Key Exchange](#tls-and-post-quantum-key-exchange)
- [FIPS 140-2/3 Mode](#fips-140-23-mode)
- [Security Controls](#security-controls)
- [Compliance Mapping](#compliance-mapping)
- [Audit Logging](#audit-logging)
- [Proxy Support](#proxy-support)
- [Known Limitations](#known-limitations)
- [Changelog](#changelog)
- [Related Projects](#related-projects)
- [Contributing](#contributing)
- [License](#license)

---

## Features

- **Drop-in MinIO Client config** — reads `~/.mc/config.json` aliases directly;
  no separate configuration file required.
- **Structured JSONL output** — JSON result record to stdout; audit records to
  stderr.  Compatible with `jq`, NATS, and SIEM ingestion.
- **Automatic key resolution** — if the target key is omitted or ends with `/`,
  the source filename is appended automatically.
- **Single-part and multipart uploads** — files below the threshold (default
  100 MiB) use `PutObject`; larger files use `CreateMultipartUpload` +
  `UploadPart` + `CompleteMultipartUpload` with configurable part sizes.
- **Automatic multipart abort** — if any part upload fails, the incomplete
  multipart upload is aborted to prevent orphaned parts.
- **Content-type auto-detection** — detects MIME type from file extension;
  overridable via `--content-type`.
- **Optional KMAC512-384 integrity tagging** — when `--kmac-key` is provided,
  the file is hashed with KMAC512 (NIST SP 800-185) truncated to 384 bits
  before upload, and the base64-encoded result is attached as
  `x-amz-meta-kmac512-384` object metadata.  The tag is preserved by
  `CopyObject` and `s3-mv`.
- **Post-quantum TLS** — prefers X25519MLKEM768 (hybrid ML-KEM-768 + X25519)
  during TLS 1.3 handshake via `rustls` + `aws-lc-rs`.
- **Credential protection** — HMAC keys held as `secrecy::SecretString` (zeroed
  on drop, `Debug`-safe).
- **Config file permission enforcement** — refuses to start if
  `~/.mc/config.json` is group- or world-readable on Unix (mode `0600`
  required).
- **Audit logging** — emits JSONL audit records (startup, completion, abort) to
  stderr with a UUID v7 `run_id` for correlation.  Includes `kmac_attached`
  indicator and `kmac512_384` value in completion record.
- **Input validation** — enforces maximum lengths on target strings, config
  files, CA bundles, part counts, and validates KMAC key hex encoding upfront.
- **Timeouts** — connect (10 s), operation (300 s), and per-attempt (120 s)
  timeouts prevent indefinite hangs.
- **Custom CA bundle** — `--ca-bundle` adds PEM-encoded certificates on top of
  platform-native roots (does not replace them).
- **mimalloc allocator** — uses mimalloc (secure mode) for improved allocation
  performance with guard pages, randomized allocation, and encrypted free lists.

---

## Requirements

| Requirement       | Version       | Notes                                        |
|-------------------|---------------|----------------------------------------------|
| Rust toolchain    | >= 1.85       | Edition 2024 support                         |
| C compiler        | clang or gcc  | Required by `aws-lc-rs` to build `aws-lc`   |
| CMake             | >= 3.10       | Required on some platforms for `aws-lc`      |
| Go toolchain      | >= 1.22       | **Only** required for `--features fips`      |

---

## Build

### Standard (non-FIPS)

```bash
cargo build --release
```

### FIPS 140-2/3 validated cryptography

```bash
cargo build --release --features fips
```

### Static musl build (Linux)

```bash
cargo build --release --target x86_64-unknown-linux-musl
```

---

## Installation

```bash
cp target/release/s3-put /usr/local/bin/
chmod 755 /usr/local/bin/s3-put
```

---

## Configuration

`s3-put` reads the standard MinIO Client configuration file at
`~/.mc/config.json`.

### Example `~/.mc/config.json`

```json
{
  "version": "10",
  "aliases": {
    "myminio": {
      "url": "https://minio.example.com",
      "accessKey": "AKIAIOSFODNN7EXAMPLE",
      "secretKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
      "api": "S3v4",
      "path": "auto"
    }
  }
}
```

### File permissions (Unix)

```bash
chmod 600 ~/.mc/config.json
```

---

## Usage

### Simple upload (key derived from filename)

```bash
s3-put ./report.pdf myminio/docs-bucket/
```

### Upload with explicit key

```bash
s3-put ./report.pdf myminio/docs-bucket/2026/Q2/quarterly-report.pdf
```

### Upload with KMAC512-384 integrity tag

```bash
s3-put ./sensors.parquet myminio/telemetry-bucket/raw/2026/06/09/ \
  --kmac-key "0123456789abcdef0123456789abcdef" \
  --kmac-custom "durham-telemetry-v2"
```

### Upload without KMAC (default — no extra metadata)

```bash
s3-put ./data.csv myminio/analytics-bucket
```

### Custom content-type and storage class

```bash
s3-put ./archive.tar.gz ibmcos/cold-bucket/backups/ \
  --content-type application/gzip \
  --storage-class GLACIER
```

### Large file with tuned multipart

```bash
s3-put ./database-dump.sql.gz myminio/backup-bucket/ \
  --multipart-threshold-mib 50 \
  --part-size-mib 25
```

### Custom CA bundle

```bash
s3-put ./data.json myminio/internal-bucket/ \
  --ca-bundle /etc/pki/tls/certs/internal-ca.pem
```

### Verify KMAC metadata after upload

```bash
mc stat --json myminio/telemetry-bucket/raw/2026/06/09/sensors.parquet \
  | jq '.metadata["X-Amz-Meta-Kmac512-384"]'
```

### Pipe result to jq

```bash
s3-put ./metrics.parquet myminio/analytics/ | jq '{etag, kmac512_384}'
```

### CLI reference

```
s3-put [OPTIONS] <SOURCE> <TARGET>

Arguments:
  <SOURCE>    Local file to upload
  <TARGET>    Target in the form alias/bucket[/key]

Options:
      --config <PATH>                  Path to mc config file
                                       [default: ~/.mc/config.json]
                                       [env: MC_CONFIG_DIR]
      --region <REGION>                Override region [default: us-east-1]
      --content-type <MIME>            Override content-type
      --storage-class <CLASS>          Storage class (e.g. STANDARD, GLACIER)
      --multipart-threshold-mib <N>    Multipart threshold [default: 100]
      --part-size-mib <N>              Part size for multipart [default: 10]
      --ca-bundle <PATH>               PEM CA bundle to add to native roots
      --verbose                        Emit detailed error information
      --kmac-key <HEX_KEY>             KMAC512-384 key (hex-encoded, optional)
      --kmac-custom <STRING>           KMAC customization string [default: ""]
  -h, --help                           Print help
```

---

## Key Resolution

| Target form | Resolved key |
|-------------|-------------|
| `alias/bucket` | `<source filename>` |
| `alias/bucket/` | `<source filename>` |
| `alias/bucket/prefix/` | `prefix/<source filename>` |
| `alias/bucket/explicit-key.ext` | `explicit-key.ext` |
| `alias/bucket/path/to/renamed.ext` | `path/to/renamed.ext` |

---

## Upload Strategy

| File size | Method | API calls |
|-----------|--------|-----------|
| <= threshold (default 100 MiB) | Single `PutObject` | 1 |
| > threshold | Multipart | 1 `CreateMultipartUpload` + N `UploadPart` + 1 `CompleteMultipartUpload` |
| > threshold (failure) | Abort | `AbortMultipartUpload` called automatically |

### Tuning

| Flag | Default | Minimum | Purpose |
|------|---------|---------|---------|
| `--multipart-threshold-mib` | 100 | 5 | Switch to multipart above this size |
| `--part-size-mib` | 10 | 5 | Chunk size per part |

Maximum parts per upload: 10,000 (S3 limit).  The application validates this
before starting the upload and advises increasing `--part-size-mib` if needed.

---

## KMAC512-384 Integrity Tagging

### Overview

When `--kmac-key` is provided, `s3-put` computes a KMAC512 (NIST SP 800-185)
hash of the source file, truncated to 384 bits (48 bytes), and attaches the
base64-encoded result as `x-amz-meta-kmac512-384` on the uploaded object.

This provides a **keyed integrity tag** that:

- Can be verified by any party that holds the KMAC key
- Is preserved by `CopyObject` (`metadata_directive: COPY`) and `s3-mv`
- Travels with the object as S3 user-defined metadata
- Uses a NIST-standardized post-quantum-aligned construction

### How it works

```
Source file ──► stream in 8 KiB chunks ──► KMAC512(key, customization)
                                                │
                                         finalize to 48 bytes (384 bits)
                                                │
                                         base64 encode (64 characters)
                                                │
                                         attach as x-amz-meta-kmac512-384
```

The file is streamed through the KMAC — never fully buffered in memory.

### When `--kmac-key` is NOT provided

- No KMAC computation occurs
- No `x-amz-meta-kmac512-384` metadata is attached
- `kmac512_384` is omitted from the JSON output
- `kmac_attached: false` in the audit start record
- Zero runtime cost — the KMAC code path is not executed

### KMAC key management

| Concern | Guidance |
|---------|---------|
| Key format | Hex-encoded on the CLI (e.g., `"0123456789abcdef..."`) |
| Key length | Any length; 32 bytes (256 bits) recommended |
| Key storage | Do NOT hardcode in scripts.  Use environment variables, secrets managers, or secure key files. |
| Key rotation | Rotate periodically.  Objects tagged with old keys remain verifiable if you retain the old key. |
| Customization string | Use for domain separation (e.g., `"durham-telemetry-v2"`).  Different customization strings produce different tags even with the same key and file. |

### Why KMAC512-384

| Property | Value |
|----------|-------|
| NIST standard | SP 800-185 |
| Underlying primitive | Keccak (sponge construction) |
| Classical security | 256-bit |
| Quantum security (Grover) | ~192-bit |
| Domain separation | Built-in customization parameter (S) |
| Output flexibility | XOF — truncation is spec-defined |
| Base64 output length | 64 characters (fits S3 metadata limits) |

### Verifying the tag

```bash
# After upload — read the tag from object metadata
mc stat --json alias/bucket/key | jq -r '.metadata["X-Amz-Meta-Kmac512-384"]'

# Recompute locally (using any KMAC512 implementation)
# and compare the base64 strings
```

---

## Output Schema

### Upload result (stdout)

```json
{
  "status": "success",
  "type": "upload",
  "source": "./data/sensors.csv",
  "bucket": "telemetry-bucket",
  "key": "raw/2026/06/08/sensors.csv",
  "size": 4096,
  "etag": "\"d41d8cd98f00b204e9800998ecf8427e\"",
  "content_type": "text/csv",
  "upload_method": "single",
  "kmac512_384": "RkFLRV9CQVNFNF9TVFJJTkdfSEVSRV9GT1JfREVNT05TVFJBVEFUSU9O",
  "duration_ms": 347
}
```

### Upload without KMAC (stdout)

```json
{
  "status": "success",
  "type": "upload",
  "source": "./data/sensors.csv",
  "bucket": "telemetry-bucket",
  "key": "raw/2026/06/08/sensors.csv",
  "size": 4096,
  "etag": "\"d41d8cd98f00b204e9800998ecf8427e\"",
  "content_type": "text/csv",
  "upload_method": "single",
  "duration_ms": 347
}
```

> **Note:** `kmac512_384` is omitted entirely when `--kmac-key` is not used.

### Error record (stderr)

```json
{
  "status": "error",
  "error": "alias 'bogus' not found in config"
}
```

### Field reference

| Field           | Type   | Present          | Description                              |
|-----------------|--------|------------------|------------------------------------------|
| `status`        | string | always           | `"success"` or `"error"`                |
| `type`          | string | on success       | `"upload"`                               |
| `source`        | string | on success       | Local source file path                   |
| `bucket`        | string | on success       | Target bucket name                       |
| `key`           | string | on success       | Resolved S3 object key                   |
| `size`          | u64    | on success       | File size in bytes                        |
| `etag`          | string | on success       | Server-returned entity tag               |
| `content_type`  | string | on success       | MIME type used for upload                |
| `upload_method` | string | on success       | `"single"` or `"multipart"`             |
| `parts`         | u64    | multipart only   | Number of parts uploaded                 |
| `kmac512_384`   | string | when `--kmac-key` used | Base64-encoded KMAC512-384 tag     |
| `duration_ms`   | u128   | on success       | Total upload duration in milliseconds    |
| `error`         | string | on error         | Human-readable error description         |

---

## TLS and Post-Quantum Key Exchange

The application uses **rustls** with the **aws-lc-rs** cryptographic provider.
The `prefer-post-quantum` feature ensures **X25519MLKEM768** is offered first
during TLS 1.3 handshake.

### Negotiation behaviour

1. Client offers X25519MLKEM768 first in `supported_groups`.
2. If supported, the handshake completes with hybrid PQ key exchange.
3. If not supported, falls back to X25519, then secp256r1/secp384r1.

### Verification

```bash
SSLKEYLOGFILE=/tmp/tls-keys.log s3-put ./test.txt myminio/test-bucket/
```

---

## FIPS 140-2/3 Mode

For environments requiring FIPS-validated cryptography (NIST SP 800-53 SC-13):

```bash
cargo build --release --features fips
```

Requires a Go toolchain (>= 1.22) at build time.

---

## Security Controls

### Credential protection

| Control                    | Implementation                                              |
|----------------------------|-------------------------------------------------------------|
| Memory zeroing             | `secrecy::SecretString` zeroes credential memory on drop    |
| Debug redaction            | `SecretString` prints `[REDACTED]` in `Debug` output        |
| Config file permissions    | Enforces `0600` on Unix; refuses to start if too permissive |
| Error message sanitization | Endpoint URLs and alias lists hidden unless `--verbose`     |

### TLS hardening

| Control                    | Implementation                                              |
|----------------------------|-------------------------------------------------------------|
| Post-quantum KX            | X25519MLKEM768 preferred via `prefer-post-quantum`          |
| FIPS mode                  | Optional `--features fips` build                            |
| CA bundle isolation        | `--ca-bundle` adds to (not replaces) platform-native roots  |
| CA bundle warning          | Warning emitted to stderr when custom trust store is active |

### Integrity tagging

| Control                    | Implementation                                              |
|----------------------------|-------------------------------------------------------------|
| KMAC512-384 (optional)     | Keyed integrity tag via NIST SP 800-185 KMAC construction   |
| Streaming hash             | File streamed in 8 KiB chunks — never fully buffered        |
| Key validation             | Hex key decoded and validated before any S3 calls           |
| Metadata attachment        | `x-amz-meta-kmac512-384` — preserved by CopyObject/s3-mv   |
| Zero cost when unused      | No computation or metadata when `--kmac-key` is not passed  |

### Input validation

| Control                    | Implementation                                              |
|----------------------------|-------------------------------------------------------------|
| Config file size limit     | Refuses files larger than 1 MiB                             |
| CA bundle size limit       | Refuses bundles larger than 10 MiB                          |
| Target string length       | Refuses targets longer than 2048 characters                 |
| Part count validation      | Refuses uploads requiring > 10,000 parts                   |
| Part size minimum          | Enforces >= 5 MiB per S3 specification                     |
| Source file validation     | Verifies source exists and is a regular file                |
| KMAC key hex validation    | Fails fast on invalid hex encoding                          |

### Timeout configuration

| Timeout    | Default | Purpose                              |
|------------|---------|--------------------------------------|
| Connect    | 10 s    | TCP + TLS handshake                  |
| Operation  | 300 s   | Total time for complete upload       |
| Attempt    | 120 s   | Single retry attempt                 |

---

## Compliance Mapping

### Credential and key management

| Control                       | 800-53        | ISO 27001 | PCI DSS 4.0 | STIG       | CIS v8.1 |
|-------------------------------|---------------|-----------|-------------|------------|----------|
| SecretString memory zeroing   | SC-12, SC-28  | A.8.24    | 3.5.1       | V-222542   | 3.11     |
| Config file permission check  | AC-3          | A.8.3     | 7.2.2       | V-222425   | 6.1      |
| Debug redaction               | SI-11         | A.8.15    | 3.3.1       | V-222658   | 3.11     |
| Error message sanitization    | SI-11         | A.8.15    | 6.2.4       | V-222609   | 16.6     |

### Cryptographic protection

| Control                       | 800-53        | ISO 27001 | PCI DSS 4.0 | STIG       | CIS v8.1 |
|-------------------------------|---------------|-----------|-------------|------------|----------|
| X25519MLKEM768 PQ KX          | SC-8(1)       | A.8.24    | 4.2.1       | V-222610   | 3.10     |
| FIPS mode (optional)          | SC-13         | A.8.24    | 4.2.1       | V-222596   | 3.10     |
| CA bundle add (not replace)   | SC-23         | A.8.24    | 4.2.1       | V-222577   | 3.10     |
| KMAC512-384 integrity tag     | SI-7          | A.8.24    | 6.2.4       | V-222542   | 3.11     |

### Audit and logging

| Control                       | 800-53        | ISO 27001 | PCI DSS 4.0 | STIG       | CIS v8.1 |
|-------------------------------|---------------|-----------|-------------|------------|----------|
| Startup audit record          | AU-2, AU-3    | A.8.15    | 10.2.1      | V-222457   | 8.2      |
| Completion audit record       | AU-2, AU-12   | A.8.15    | 10.2.1      | V-222457   | 8.2      |
| Multipart abort audit record  | AU-2, AU-12   | A.8.15    | 10.2.1      | V-222457   | 8.2      |
| UUID v7 run_id correlation    | AU-3(1)       | A.8.15    | 10.2.1.2    | V-222458   | 8.5      |

### Input validation

| Control                       | 800-53        | ISO 27001 | PCI DSS 4.0 | STIG       | CIS v8.1 |
|-------------------------------|---------------|-----------|-------------|------------|----------|
| Config file size limit        | SI-10         | A.8.28    | 6.2.4       | V-222609   | 16.6     |
| CA bundle size limit          | SI-10         | A.8.28    | 6.2.4       | V-222609   | 16.6     |
| Target string length limit    | SI-10         | A.8.28    | 6.2.4       | V-222609   | 16.6     |
| Part count validation         | SI-10         | A.8.28    | 6.2.4       | V-222607   | 16.6     |
| KMAC key hex validation       | SI-10         | A.8.28    | 6.2.4       | V-222607   | 16.6     |

---

## Audit Logging

All audit records are emitted to **stderr** as JSONL.  Each record includes a
`run_id` (UUID v7) for correlation.

### Startup record

```json
{
  "event": "put_object_start",
  "run_id": "0192f3a4-5b6c-7d8e-9f01-234567890abc",
  "alias": "myminio",
  "endpoint": "https://minio.example.com",
  "bucket": "docs-bucket",
  "key": "2026/Q2/report.pdf",
  "source": "./report.pdf",
  "file_size": 1048576,
  "upload_method": "single",
  "content_type": "application/pdf",
  "region": "us-east-1",
  "path_style": true,
  "pq_kx": "X25519MLKEM768",
  "kmac_attached": true,
  "ca_bundle": null
}
```

### Completion record

```json
{
  "event": "put_object_complete",
  "run_id": "0192f3a4-5b6c-7d8e-9f01-234567890abc",
  "alias": "myminio",
  "bucket": "docs-bucket",
  "key": "2026/Q2/report.pdf",
  "size": 1048576,
  "etag": "\"d41d8cd98f00b204e9800998ecf8427e\"",
  "upload_method": "single",
  "kmac512_384": "RkFLRV9CQVNFNF9TVFJJTkdfSEVSRV9GT1JfREVNT05TVFJBVEFUSU9O",
  "duration_ms": 523,
  "outcome": "success"
}
```

> **Note:** `kmac512_384` is omitted from the completion record when
> `--kmac-key` is not used.

### Log integrity

Audit log integrity protection is an **operational responsibility**.
The consuming pipeline must enforce write-once semantics or cryptographic
log chaining per NIST SP 800-53 AU-9.

---

## Proxy Support

The underlying HTTP client respects:

| Variable       | Example                          | Description                   |
|----------------|----------------------------------|-------------------------------|
| `HTTPS_PROXY`  | `http://proxy.example.com:3128`  | HTTPS proxy endpoint          |
| `HTTP_PROXY`   | `http://proxy.example.com:3128`  | HTTP proxy endpoint           |
| `NO_PROXY`     | `localhost,127.0.0.1,.internal`  | Bypass proxy for these hosts  |

---

## Known Limitations

1. **Static HMAC keys only** — STS / AssumeRole / session tokens not yet
   supported.
2. **No cryptoperiod enforcement** — no warning when keys exceed recommended
   rotation interval.
3. **No alias access restriction** — any user with config file access can use
   any alias.
4. **No TOCTOU hardening** — config file read without `O_NOFOLLOW`.
5. **Sequential part uploads** — multipart parts are uploaded sequentially, not
   in parallel.  Parallel upload is planned for a future release.
6. **No checksum verification** — the application does not compute or verify
   SHA-256 / CRC32C checksums against the server response.  Planned.
7. **KMAC key on CLI** — the KMAC key is passed as a hex string on the command
   line, which may be visible in process listings.  Use environment variables
   or wrapper scripts in production.  Planned: `--kmac-key-file` flag.

---

## Changelog

### v0.3.0 (2026-06-09)

- **Added:** Optional KMAC512-384 integrity tagging via `--kmac-key` and
  `--kmac-custom`.  Computes NIST SP 800-185 KMAC512 truncated to 384 bits
  over the source file and attaches the base64-encoded result as
  `x-amz-meta-kmac512-384` object metadata.
- **Added:** `tiny-keccak`, `base64`, and `hex` dependencies.
- **Added:** `kmac512_384` field in `UploadRecord` and `AuditCompleteRecord`.
- **Added:** `kmac_attached` field in `AuditStartRecord`.
- **Added:** `kmac_b64` field in `UploadContext` for multipart uploads.
- **Added:** `mimalloc` (secure mode) as global allocator.
- **Security:** KMAC key hex validation fails fast before any S3 calls (SI-10).
- **Security:** File is streamed through KMAC in 8 KiB chunks — never fully
  buffered.
- **Security:** Zero runtime cost when `--kmac-key` is not provided.

### v0.2.0

- Clippy-clean pass.
- `UploadContext` struct to avoid `too_many_arguments`.
- `div_ceil` and `saturating_sub` fixes.
- `rustfmt`-clean pass.

### v0.1.0

- Initial release.

---

## Related Projects

- [s3-ls-json](../s3-ls-json/) — list and filter S3 objects with JSONL output.
- [s3-get](../s3-get/) — download files from S3.
- [s3-mv](../s3-mv/) — move objects within S3 (server-side).

All four tools share the same config format, security controls, and PQ TLS
stack.

---

## Contributing

1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/my-feature`).
3. Ensure `cargo clippy -- -D warnings` passes.
4. Ensure `cargo test` passes.
5. Run `cargo audit` and resolve any advisories.
6. Submit a pull request.

---

## License

This project is licensed under the [MIT License](LICENSE).
