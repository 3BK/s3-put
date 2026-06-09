use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use aws_config::BehaviorVersion;
use aws_credential_types::Credentials;
use aws_sdk_s3::Client;
use aws_sdk_s3::config::Region;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::{CompletedMultipartUpload, CompletedPart};
use aws_smithy_http_client::tls;
use aws_smithy_types::byte_stream::Length;
use aws_smithy_types::timeout::TimeoutConfig;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use clap::Parser;
use mimalloc::MiMalloc;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use tiny_keccak::{Hasher, Kmac};
use uuid::Uuid;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

// ──────────────────────────────────────────────
//  Constants
// ──────────────────────────────────────────────

const DEFAULT_REGION: &str = "us-east-1";
const CONNECT_TIMEOUT_SECS: u64 = 10;
const OPERATION_TIMEOUT_SECS: u64 = 300; // uploads can be large
const ATTEMPT_TIMEOUT_SECS: u64 = 120;
const MAX_CONFIG_SIZE: u64 = 1_048_576; // 1 MiB
const MAX_CA_BUNDLE_SIZE: u64 = 10_485_760; // 10 MiB
const MAX_TARGET_LEN: usize = 2048;
const MIN_PART_SIZE: u64 = 5 * 1024 * 1024; // 5 MiB — S3 minimum
const MAX_PARTS: u64 = 10_000; // S3 maximum
const KMAC_READ_BUF: usize = 8192; // 8 KiB streaming hash buffer

// ──────────────────────────────────────────────
//  CLI
// ──────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "s3-put",
    about = "Upload a file to an S3-compatible endpoint using ~/.mc/config.json aliases.\n\
             Emits a JSON result record to stdout (mc put equivalent).\n\n\
             TLS uses rustls + aws-lc-rs with X25519MLKEM768 as the preferred key exchange."
)]
struct Args {
    /// Local file to upload
    source: PathBuf,

    /// Target in the form  alias/bucket[/key]
    /// If key is omitted or ends with '/', the source filename is appended.
    target: String,

    /// Path to mc config file (default: ~/.mc/config.json)
    #[arg(long, env = "MC_CONFIG_DIR")]
    config: Option<PathBuf>,

    /// Override the region (default: us-east-1)
    #[arg(long)]
    region: Option<String>,

    /// Override content-type (default: detected from file extension)
    #[arg(long)]
    content_type: Option<String>,

    /// Storage class (e.g. STANDARD, REDUCED_REDUNDANCY, STANDARD_IA, GLACIER)
    #[arg(long)]
    storage_class: Option<String>,

    /// Multipart upload threshold in MiB (default: 100).
    /// Files larger than this are uploaded using multipart.
    #[arg(long, default_value_t = 100)]
    multipart_threshold_mib: u64,

    /// Part size for multipart uploads in MiB (default: 10, minimum: 5).
    #[arg(long, default_value_t = 10)]
    part_size_mib: u64,

    /// Path to a PEM-encoded CA bundle to add to platform-native roots.
    #[arg(long)]
    ca_bundle: Option<PathBuf>,

    /// Emit detailed error information.
    #[arg(long, default_value_t = false)]
    verbose: bool,

    /// KMAC512-384 key (hex-encoded) for computing x-amz-meta-kmac512-384.
    /// If set, the file is hashed with KMAC512 truncated to 384 bits
    /// before upload, and the base64-encoded result is attached as
    /// object metadata.  If omitted, no KMAC is computed.
    #[arg(long, value_name = "HEX_KEY")]
    kmac_key: Option<String>,

    /// KMAC customization string (SP 800-185 domain separator).
    /// Only used when --kmac-key is set.  Default: "" (empty).
    #[arg(long, value_name = "STRING", default_value = "")]
    kmac_custom: String,
}

// ──────────────────────────────────────────────
//  MinIO config.json model  (~/.mc/config.json)
// ──────────────────────────────────────────────

#[derive(Deserialize)]
struct McConfig {
    #[allow(dead_code)]
    version: String,
    aliases: HashMap<String, McAlias>,
}

/// Credentials held as [`SecretString`] (CWE-256/316).
/// `Debug` on `SecretString` emits `[REDACTED]` (CWE-532).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct McAlias {
    url: String,
    access_key: SecretString,
    secret_key: SecretString,
    #[allow(dead_code)]
    api: Option<String>,
    path: Option<String>,
}

// ──────────────────────────────────────────────
//  JSON output models
// ──────────────────────────────────────────────

#[derive(Serialize)]
struct UploadRecord {
    status: &'static str,
    #[serde(rename = "type")]
    record_type: &'static str,
    source: String,
    bucket: String,
    key: String,
    size: u64,
    etag: String,
    content_type: String,
    upload_method: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    parts: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kmac512_384: Option<String>,
    duration_ms: u128,
}

#[derive(Serialize)]
struct ErrorRecord {
    status: &'static str,
    error: String,
}

#[derive(Serialize)]
struct AuditStartRecord<'a> {
    event: &'static str,
    run_id: String,
    alias: &'a str,
    endpoint: &'a str,
    bucket: &'a str,
    key: &'a str,
    source: &'a str,
    file_size: u64,
    upload_method: &'a str,
    content_type: &'a str,
    region: &'a str,
    path_style: bool,
    pq_kx: &'static str,
    kmac_attached: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    ca_bundle: Option<&'a str>,
}

#[derive(Serialize)]
struct AuditCompleteRecord<'a> {
    event: &'static str,
    run_id: &'a str,
    alias: &'a str,
    bucket: &'a str,
    key: &'a str,
    size: u64,
    etag: &'a str,
    upload_method: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    parts: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kmac512_384: Option<&'a str>,
    duration_ms: u128,
    outcome: &'static str,
}

// ──────────────────────────────────────────────
//  Multipart upload context
// ──────────────────────────────────────────────

/// Bundles shared parameters for multipart upload functions,
/// avoiding clippy::too_many_arguments.
struct UploadContext<'a> {
    client: &'a Client,
    bucket: &'a str,
    key: &'a str,
    source_path: &'a Path,
    file_size: u64,
    content_type: &'a str,
    storage_class: Option<&'a str>,
    part_size: u64,
    verbose: bool,
    kmac_b64: Option<&'a str>,
}

// ──────────────────────────────────────────────
//  KMAC512-384
// ──────────────────────────────────────────────

/// Compute KMAC512 truncated to 384 bits (48 bytes) over a file,
/// returning the result as a base64-encoded string.
///
/// - `key`: the KMAC key (shared secret or per-pipeline key)
/// - `customization`: SP 800-185 domain-separation string (S)
/// - `path`: file to hash
///
/// The file is streamed in 8 KiB chunks — never fully buffered.
fn kmac512_384_file(key: &[u8], customization: &[u8], path: &Path) -> Result<String> {
    let mut kmac = Kmac::v512(key, customization);

    let mut file =
        std::fs::File::open(path).with_context(|| format!("cannot open {}", path.display()))?;

    let mut buf = [0u8; KMAC_READ_BUF];
    loop {
        let n = file
            .read(&mut buf)
            .with_context(|| format!("error reading {}", path.display()))?;
        if n == 0 {
            break;
        }
        kmac.update(&buf[..n]);
    }

    // Finalize into 48 bytes (384 bits)
    let mut output = [0u8; 48];
    kmac.finalize(&mut output);

    Ok(BASE64.encode(output))
}

// ──────────────────────────────────────────────
//  Helpers
// ──────────────────────────────────────────────

fn config_path(override_path: Option<&PathBuf>) -> Result<PathBuf> {
    if let Some(p) = override_path {
        return Ok(p.clone());
    }
    let home = dirs::home_dir().context("cannot determine home directory")?;
    Ok(home.join(".mc").join("config.json"))
}

/// CWE-732: verify config file is not group/other accessible.
#[cfg(unix)]
fn check_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let meta =
        std::fs::metadata(path).with_context(|| format!("cannot stat {}", path.display()))?;
    let mode = meta.mode();
    if mode & 0o077 != 0 {
        bail!(
            "{} is accessible by group/others (mode {:o}). \
             Expected 0600. Fix with: chmod 600 {}",
            path.display(),
            mode & 0o777,
            path.display(),
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

fn load_config(path: &Path) -> Result<McConfig> {
    // CWE-400 / SI-10: enforce config file size limit
    let meta =
        std::fs::metadata(path).with_context(|| format!("cannot stat {}", path.display()))?;
    if meta.len() > MAX_CONFIG_SIZE {
        bail!(
            "config file {} exceeds maximum allowed size ({} bytes)",
            path.display(),
            MAX_CONFIG_SIZE,
        );
    }
    let data = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let cfg: McConfig = serde_json::from_str(&data)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    Ok(cfg)
}

/// Split "alias/bucket/key/parts" → (alias, bucket, key_or_prefix).
/// The key component is optional and may be empty.
fn parse_target(input: &str) -> Result<(String, String, String)> {
    let trimmed = input.trim_start_matches('/');
    let mut parts = trimmed.splitn(3, '/');

    let alias = parts
        .next()
        .filter(|s| !s.is_empty())
        .context("target must start with an alias name")?
        .to_string();

    let bucket = parts
        .next()
        .filter(|s| !s.is_empty())
        .context("target must include a bucket name after the alias (alias/bucket)")?
        .to_string();

    let key = parts.next().unwrap_or("").to_string();

    Ok((alias, bucket, key))
}

/// Resolve the S3 object key.
///
/// - If `target_key` is empty or ends with `/`, the source filename is appended.
/// - Otherwise `target_key` is used as-is.
fn resolve_object_key(target_key: &str, source_path: &Path) -> Result<String> {
    let filename = source_path
        .file_name()
        .and_then(|n| n.to_str())
        .context("cannot determine filename from source path")?;

    if target_key.is_empty() || target_key.ends_with('/') {
        Ok(format!("{}{}", target_key, filename))
    } else {
        Ok(target_key.to_string())
    }
}

fn resolve_path_style(alias: &McAlias) -> bool {
    match alias.path.as_deref() {
        Some("on") => true,
        Some("off") => false,
        _ => !alias.url.contains("amazonaws.com"),
    }
}

/// Detect content-type from file extension.
fn content_type_from_ext(path: &Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()) {
        Some("json") => "application/json",
        Some("jsonl" | "ndjson") => "application/x-ndjson",
        Some("csv") => "text/csv",
        Some("tsv") => "text/tab-separated-values",
        Some("txt" | "log" | "md") => "text/plain",
        Some("html" | "htm") => "text/html",
        Some("xml") => "application/xml",
        Some("pdf") => "application/pdf",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("svg") => "image/svg+xml",
        Some("webp") => "image/webp",
        Some("gz" | "gzip") => "application/gzip",
        Some("tar") => "application/x-tar",
        Some("zip") => "application/zip",
        Some("zst" | "zstd") => "application/zstd",
        Some("bz2") => "application/x-bzip2",
        Some("xz") => "application/x-xz",
        Some("7z") => "application/x-7z-compressed",
        Some("parquet") => "application/vnd.apache.parquet",
        Some("avro") => "application/avro",
        Some("orc") => "application/x-orc",
        Some("yaml" | "yml") => "application/yaml",
        Some("toml") => "application/toml",
        Some("wasm") => "application/wasm",
        Some("bin" | "dat") => "application/octet-stream",
        _ => "application/octet-stream",
    }
}

// ──────────────────────────────────────────────
//  Main
// ──────────────────────────────────────────────

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        let err = ErrorRecord {
            status: "error",
            error: format!("{:#}", e),
        };
        eprintln!("{}", serde_json::to_string(&err).unwrap_or_default());
        process::exit(1);
    }
}

async fn run() -> Result<()> {
    let args = Args::parse();
    let run_id = Uuid::now_v7().to_string();
    let started = Instant::now();

    // ── Input validation (SI-10) ────────────────
    if args.target.len() > MAX_TARGET_LEN {
        bail!(
            "target string exceeds maximum allowed length ({} chars)",
            MAX_TARGET_LEN,
        );
    }

    let part_size = args.part_size_mib * 1024 * 1024;
    if part_size < MIN_PART_SIZE {
        bail!(
            "part size must be at least 5 MiB (got {} MiB)",
            args.part_size_mib,
        );
    }
    let multipart_threshold = args.multipart_threshold_mib * 1024 * 1024;

    // ── Validate source file ────────────────────
    let source_path = &args.source;
    let source_meta = std::fs::metadata(source_path)
        .with_context(|| format!("cannot access source file {}", source_path.display()))?;
    if !source_meta.is_file() {
        bail!("{} is not a regular file", source_path.display());
    }
    let file_size = source_meta.len();

    // Validate multipart constraints
    if file_size > multipart_threshold {
        let chunk_count = file_size.div_ceil(part_size);
        if chunk_count > MAX_PARTS {
            bail!(
                "file requires {} parts but S3 maximum is {}. \
                 Increase --part-size-mib.",
                chunk_count,
                MAX_PARTS,
            );
        }
    }

    // ── Compute KMAC512-384 if requested ────────
    let kmac_b64 = if let Some(ref hex_key) = args.kmac_key {
        let key_bytes =
            hex::decode(hex_key).context("invalid hex in --kmac-key")?;
        let b64 = kmac512_384_file(&key_bytes, args.kmac_custom.as_bytes(), source_path)?;
        Some(b64)
    } else {
        None
    };

    // ── 1. Load mc config ───────────────────────
    let cfg_path = config_path(args.config.as_ref())?;
    check_permissions(&cfg_path)?;
    let cfg = load_config(&cfg_path)?;

    // ── 2. Resolve alias, bucket, key ───────────
    let (alias_name, bucket, target_key) = parse_target(&args.target)?;
    let alias = cfg.aliases.get(&alias_name).with_context(|| {
        if args.verbose {
            let known: Vec<&String> = cfg.aliases.keys().collect();
            format!(
                "alias '{}' not found in {}  (known aliases: {:?})",
                alias_name,
                cfg_path.display(),
                known,
            )
        } else {
            format!("alias '{}' not found in config", alias_name)
        }
    })?;

    let key = resolve_object_key(&target_key, source_path)?;
    let force_path = resolve_path_style(alias);
    let region_str = args.region.as_deref().unwrap_or(DEFAULT_REGION);

    let content_type = args
        .content_type
        .as_deref()
        .unwrap_or_else(|| content_type_from_ext(source_path))
        .to_string();

    let upload_method_label = if file_size > multipart_threshold {
        "multipart"
    } else {
        "single"
    };

    // ── 3. Build HTTPS client with PQ KX ────────
    let mut builder = aws_smithy_http_client::Builder::new().tls_provider(tls::Provider::Rustls(
        tls::rustls_provider::CryptoMode::AwsLc,
    ));

    if let Some(ca_path) = &args.ca_bundle {
        let ca_meta = std::fs::metadata(ca_path)
            .with_context(|| format!("cannot stat CA bundle {}", ca_path.display()))?;
        if ca_meta.len() > MAX_CA_BUNDLE_SIZE {
            bail!(
                "CA bundle {} exceeds maximum allowed size ({} bytes)",
                ca_path.display(),
                MAX_CA_BUNDLE_SIZE,
            );
        }
        let pem = std::fs::read(ca_path)
            .with_context(|| format!("failed to read CA bundle {}", ca_path.display()))?;

        let trust_store = tls::TrustStore::default().with_pem_certificate(pem);

        let tls_ctx = tls::TlsContext::builder()
            .with_trust_store(trust_store)
            .build()
            .context("failed to build TLS context from CA bundle")?;

        builder = builder.tls_context(tls_ctx);

        eprintln!(
            "{{\"event\":\"ca_bundle_loaded\",\"run_id\":\"{}\",\"path\":\"{}\"}}",
            run_id,
            ca_path.display(),
        );
    }

    let http_client = builder.build_https();

    // ── 4. Build S3 client ──────────────────────
    let creds = Credentials::new(
        alias.access_key.expose_secret().to_string(),
        alias.secret_key.expose_secret().to_string(),
        None,
        None,
        "mc-config",
    );

    let timeout_config = TimeoutConfig::builder()
        .connect_timeout(Duration::from_secs(CONNECT_TIMEOUT_SECS))
        .operation_timeout(Duration::from_secs(OPERATION_TIMEOUT_SECS))
        .operation_attempt_timeout(Duration::from_secs(ATTEMPT_TIMEOUT_SECS))
        .build();

    let shared_config = aws_config::defaults(BehaviorVersion::latest())
        .region(Region::new(region_str.to_string()))
        .credentials_provider(creds)
        .http_client(http_client)
        .timeout_config(timeout_config)
        .load()
        .await;

    let s3_config = aws_sdk_s3::config::Builder::from(&shared_config)
        .endpoint_url(&alias.url)
        .force_path_style(force_path)
        .build();

    let client = Client::from_conf(s3_config);

    // ── 5. Audit start record (CWE-778) ─────────
    let source_display = source_path.display().to_string();
    let audit_start = AuditStartRecord {
        event: "put_object_start",
        run_id: run_id.clone(),
        alias: &alias_name,
        endpoint: &alias.url,
        bucket: &bucket,
        key: &key,
        source: &source_display,
        file_size,
        upload_method: upload_method_label,
        content_type: &content_type,
        region: region_str,
        path_style: force_path,
        pq_kx: "X25519MLKEM768",
        kmac_attached: kmac_b64.is_some(),
        ca_bundle: args.ca_bundle.as_ref().map(|p| p.to_str().unwrap_or("?")),
    };
    eprintln!("{}", serde_json::to_string(&audit_start)?);

    // ── 6. Upload ───────────────────────────────
    let (etag, parts_count) = if file_size > multipart_threshold {
        let ctx = UploadContext {
            client: &client,
            bucket: &bucket,
            key: &key,
            source_path,
            file_size,
            content_type: &content_type,
            storage_class: args.storage_class.as_deref(),
            part_size,
            verbose: args.verbose,
            kmac_b64: kmac_b64.as_deref(),
        };
        do_multipart_upload(&ctx).await?
    } else {
        let etag = do_single_upload(
            &client,
            &bucket,
            &key,
            source_path,
            &content_type,
            args.storage_class.as_deref(),
            kmac_b64.as_deref(),
            args.verbose,
        )
        .await?;
        (etag, None)
    };

    let duration_ms = started.elapsed().as_millis();

    // ── 7. Emit result to stdout ────────────────
    let record = UploadRecord {
        status: "success",
        record_type: "upload",
        source: source_display.clone(),
        bucket: bucket.clone(),
        key: key.clone(),
        size: file_size,
        etag: etag.clone(),
        content_type: content_type.clone(),
        upload_method: upload_method_label,
        parts: parts_count,
        kmac512_384: kmac_b64.clone(),
        duration_ms,
    };
    println!("{}", serde_json::to_string(&record)?);

    // ── 8. Audit completion record ──────────────
    let audit_complete = AuditCompleteRecord {
        event: "put_object_complete",
        run_id: &run_id,
        alias: &alias_name,
        bucket: &bucket,
        key: &key,
        size: file_size,
        etag: &etag,
        upload_method: upload_method_label,
        parts: parts_count,
        kmac512_384: kmac_b64.as_deref(),
        duration_ms,
        outcome: "success",
    };
    eprintln!("{}", serde_json::to_string(&audit_complete)?);

    Ok(())
}

// ──────────────────────────────────────────────
//  Single-part upload (PutObject)
// ──────────────────────────────────────────────

async fn do_single_upload(
    client: &Client,
    bucket: &str,
    key: &str,
    source_path: &Path,
    content_type: &str,
    storage_class: Option<&str>,
    kmac_b64: Option<&str>,
    verbose: bool,
) -> Result<String> {
    let body = ByteStream::from_path(source_path)
        .await
        .with_context(|| format!("failed to open {}", source_path.display()))?;

    let mut req = client
        .put_object()
        .bucket(bucket)
        .key(key)
        .content_type(content_type)
        .body(body);

    if let Some(sc) = storage_class {
        req = req.storage_class(aws_sdk_s3::types::StorageClass::from(sc));
    }

    if let Some(kmac) = kmac_b64 {
        req = req.metadata("kmac512-384", kmac);
    }

    let resp = req.send().await.with_context(|| {
        if verbose {
            format!("PutObject failed: bucket={} key={}", bucket, key)
        } else {
            "PutObject request failed".to_string()
        }
    })?;

    let etag = resp.e_tag().unwrap_or_default().to_string();

    Ok(etag)
}

// ──────────────────────────────────────────────
//  Multipart upload
// ──────────────────────────────────────────────

async fn do_multipart_upload(ctx: &UploadContext<'_>) -> Result<(String, Option<u64>)> {
    // ── Create multipart upload ─────────────────
    let mut create_req = ctx
        .client
        .create_multipart_upload()
        .bucket(ctx.bucket)
        .key(ctx.key)
        .content_type(ctx.content_type);

    if let Some(sc) = ctx.storage_class {
        create_req = create_req.storage_class(aws_sdk_s3::types::StorageClass::from(sc));
    }

    if let Some(kmac) = ctx.kmac_b64 {
        create_req = create_req.metadata("kmac512-384", kmac);
    }

    let create_resp = create_req.send().await.with_context(|| {
        if ctx.verbose {
            format!(
                "CreateMultipartUpload failed: bucket={} key={}",
                ctx.bucket, ctx.key,
            )
        } else {
            "CreateMultipartUpload request failed".to_string()
        }
    })?;

    let upload_id = create_resp
        .upload_id()
        .context("server did not return an upload ID")?
        .to_string();

    // ── Upload parts ────────────────────────────
    let result = upload_parts(ctx, &upload_id).await;

    match result {
        Ok(completed_parts) => {
            let total_parts = completed_parts.len() as u64;

            // ── Complete multipart upload ────────
            let completed = CompletedMultipartUpload::builder()
                .set_parts(Some(completed_parts))
                .build();

            let complete_resp = ctx
                .client
                .complete_multipart_upload()
                .bucket(ctx.bucket)
                .key(ctx.key)
                .upload_id(&upload_id)
                .multipart_upload(completed)
                .send()
                .await
                .with_context(|| {
                    if ctx.verbose {
                        format!(
                            "CompleteMultipartUpload failed: bucket={} key={} upload_id={}",
                            ctx.bucket, ctx.key, upload_id,
                        )
                    } else {
                        "CompleteMultipartUpload request failed".to_string()
                    }
                })?;

            let etag = complete_resp.e_tag().unwrap_or_default().to_string();

            Ok((etag, Some(total_parts)))
        }
        Err(e) => {
            // ── Abort on failure ─────────────────
            eprintln!(
                "{{\"event\":\"multipart_abort\",\"upload_id\":\"{}\",\"bucket\":\"{}\",\"key\":\"{}\"}}",
                upload_id, ctx.bucket, ctx.key,
            );

            let _ = ctx
                .client
                .abort_multipart_upload()
                .bucket(ctx.bucket)
                .key(ctx.key)
                .upload_id(&upload_id)
                .send()
                .await;

            Err(e.context("multipart upload failed — upload aborted"))
        }
    }
}

/// Upload file in chunks and return the completed parts vector.
async fn upload_parts(ctx: &UploadContext<'_>, upload_id: &str) -> Result<Vec<CompletedPart>> {
    let mut chunk_count = ctx.file_size / ctx.part_size;
    let mut last_chunk_size = ctx.file_size % ctx.part_size;

    // If the file divides evenly, the last chunk is a full part
    if last_chunk_size == 0 {
        last_chunk_size = ctx.part_size;
        chunk_count = chunk_count.saturating_sub(1);
    }
    let total_chunks = chunk_count + 1;

    // Handle zero-byte edge case (shouldn't reach here, but be safe)
    if ctx.file_size == 0 {
        bail!("cannot multipart-upload a zero-byte file");
    }

    let mut completed_parts: Vec<CompletedPart> = Vec::with_capacity(total_chunks as usize);

    for chunk_index in 0..total_chunks {
        let offset = chunk_index * ctx.part_size;
        let this_chunk = if chunk_index == total_chunks - 1 {
            last_chunk_size
        } else {
            ctx.part_size
        };

        let stream = ByteStream::read_from()
            .path(ctx.source_path)
            .offset(offset)
            .length(Length::Exact(this_chunk))
            .build()
            .await
            .with_context(|| {
                format!(
                    "failed to read chunk {} from {}",
                    chunk_index + 1,
                    ctx.source_path.display(),
                )
            })?;

        // S3 part numbers are 1-based
        let part_number = (chunk_index as i32) + 1;

        let upload_resp = ctx
            .client
            .upload_part()
            .bucket(ctx.bucket)
            .key(ctx.key)
            .upload_id(upload_id)
            .part_number(part_number)
            .body(stream)
            .send()
            .await
            .with_context(|| {
                if ctx.verbose {
                    format!(
                        "UploadPart {} failed: bucket={} key={} upload_id={}",
                        part_number, ctx.bucket, ctx.key, upload_id,
                    )
                } else {
                    format!("UploadPart {} failed", part_number)
                }
            })?;

        let etag = upload_resp
            .e_tag()
            .context("server did not return ETag for uploaded part")?
            .to_string();

        completed_parts.push(
            CompletedPart::builder()
                .e_tag(etag)
                .part_number(part_number)
                .build(),
        );
    }

    Ok(completed_parts)
}
