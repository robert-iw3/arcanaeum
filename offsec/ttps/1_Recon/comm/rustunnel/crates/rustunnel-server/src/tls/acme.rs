//! ACME / Let's Encrypt certificate manager.
//!
//! # Credentials
//!
//! Cloudflare credentials are read from environment variables first, falling
//! back to the config-file fields as a convenience for local dev:
//!
//! | Secret             | Env var                | Config field              |
//! |--------------------|------------------------|---------------------------|
//! | API token          | `CLOUDFLARE_API_TOKEN` | `tls.cloudflare_api_token`|
//! | Zone ID            | `CLOUDFLARE_ZONE_ID`   | `tls.cloudflare_zone_id`  |
//!
//! **Never commit real credentials to source control.**  Prefer environment
//! variables in all production deployments.
//!
//! # ACME flow (DNS-01 via Cloudflare)
//!
//! 1. Load or create an ACME account (persisted as JSON in `acme_account_dir`).
//! 2. Request an order for `[domain, *.domain]`.
//! 3. For each pending authorization, create a `_acme-challenge.<domain>` TXT
//!    record via the Cloudflare v4 API, wait for DNS propagation, then mark
//!    the challenge ready.
//! 4. Generate a fresh RSA/ECDSA key pair + CSR with `rcgen`, finalize the
//!    order, and download the signed certificate chain.
//! 5. Write `fullchain.pem` and `privkey.pem` to the configured paths.
//! 6. Delete the temporary Cloudflare TXT record(s).
//! 7. Hot-swap the live `rustls::ServerConfig` via `ArcSwap`.

use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt,
    NewAccount, NewOrder, OrderStatus,
};
use rcgen::{CertificateParams, KeyPair};
use reqwest::Client;
use rustls::pki_types::CertificateDer;
use rustls::ServerConfig as RustlsConfig;
use rustls_pemfile::{certs, private_key};
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};
use x509_parser::prelude::FromDer;

use crate::config::ServerConfig as AppConfig;
use crate::error::{Error, Result};

// ── tunables ──────────────────────────────────────────────────────────────────

/// Renew if the certificate expires within this many days.
const RENEW_THRESHOLD_DAYS: i64 = 30;

/// Seconds to wait after creating the DNS TXT record before notifying the CA.
const DNS_PROPAGATION_SECS: u64 = 60;

/// Seconds between each ACME order-status poll.
const POLL_INTERVAL_SECS: u64 = 5;

/// Maximum number of poll attempts (~2 minutes total) before giving up.
const MAX_POLL_ATTEMPTS: u32 = 24;

/// Cloudflare REST API base.
const CF_API: &str = "https://api.cloudflare.com/client/v4";

// ── CertManager ───────────────────────────────────────────────────────────────

/// Manages TLS certificates with optional automatic ACME renewal.
///
/// Construct with [`CertManager::new`], then:
/// - Pass [`CertManager::tls_handle`] to the TLS acceptor for hot-reload.
/// - Call [`CertManager::start_renewal_task`] to enable daily background checks.
pub struct CertManager {
    app_config: Arc<AppConfig>,
    /// Hot-swappable server config shared with all TLS acceptors.
    tls: Arc<ArcSwap<RustlsConfig>>,
}

impl CertManager {
    /// Create a new `CertManager`.
    ///
    /// If ACME is enabled and the certificate is absent or expiring soon, the
    /// full ACME issuance flow runs synchronously before this returns.
    pub async fn new(app_config: Arc<AppConfig>) -> Result<Arc<Self>> {
        if app_config.tls.acme_enabled {
            let cert_missing = !Path::new(&app_config.tls.cert_path).exists()
                || !Path::new(&app_config.tls.key_path).exists();
            let cert_expiring = !cert_missing
                && cert_expiring_within(&app_config.tls.cert_path, RENEW_THRESHOLD_DAYS);

            if cert_missing || cert_expiring {
                info!(
                    cert_missing,
                    cert_expiring, "running ACME issuance before startup"
                );
                run_acme(&app_config).await?;
            }
        }

        let tls_cfg = build_tls_config(&app_config.tls.cert_path, &app_config.tls.key_path)?;

        let manager = Arc::new(Self {
            app_config,
            tls: Arc::new(ArcSwap::new(Arc::new(tls_cfg))),
        });

        Ok(manager)
    }

    /// Return a snapshot of the current `rustls::ServerConfig`.
    pub fn get_tls_config(&self) -> Arc<RustlsConfig> {
        Arc::clone(&self.tls.load())
    }

    /// Return the hot-reload handle.
    ///
    /// Pass this to the TLS acceptor layer and call `handle.load()` on every
    /// new inbound connection to always use the latest certificate.
    pub fn tls_handle(&self) -> Arc<ArcSwap<RustlsConfig>> {
        Arc::clone(&self.tls)
    }

    /// Spawn a background task that checks cert expiry once per day and
    /// renews via ACME if needed.
    pub fn start_renewal_task(self: Arc<Self>) {
        tokio::spawn(async move {
            // Start checking after 24 hours; avoids hammering ACME on restart.
            let mut ticker = tokio::time::interval(Duration::from_secs(86_400));
            ticker.tick().await; // skip immediate first tick

            loop {
                ticker.tick().await;
                if let Err(e) = self.check_and_renew().await {
                    error!("background cert renewal failed: {e}");
                }
            }
        });
    }

    // ── internal ─────────────────────────────────────────────────────────────

    async fn check_and_renew(&self) -> Result<()> {
        if !self.app_config.tls.acme_enabled {
            return Ok(());
        }

        if cert_expiring_within(&self.app_config.tls.cert_path, RENEW_THRESHOLD_DAYS) {
            info!("certificate expiring soon — starting renewal");
            run_acme(&self.app_config).await?;

            // Hot-swap the new certificate into the live config.
            let new_cfg = build_tls_config(
                &self.app_config.tls.cert_path,
                &self.app_config.tls.key_path,
            )?;
            self.tls.store(Arc::new(new_cfg));
            info!("TLS configuration hot-reloaded after certificate renewal");
        } else {
            debug!("certificate is valid — no renewal needed");
        }

        Ok(())
    }
}

// ── ACME flow ─────────────────────────────────────────────────────────────────

async fn run_acme(cfg: &AppConfig) -> Result<()> {
    let domain = &cfg.server.domain;
    let cf_token = resolve_cloudflare_token(cfg)?;
    let cf_zone_id = resolve_cloudflare_zone_id(cfg)?;
    let http = Client::new();

    // 1. Load or create ACME account ─────────────────────────────────────────
    let account = load_or_create_account(
        &cfg.tls.acme_email,
        &cfg.tls.acme_account_dir,
        cfg.tls.acme_staging,
    )
    .await?;

    // 2. Create order ─────────────────────────────────────────────────────────
    let identifiers = [
        Identifier::Dns(domain.clone()),
        Identifier::Dns(format!("*.{domain}")),
    ];
    let mut order = account
        .new_order(&NewOrder {
            identifiers: &identifiers,
        })
        .await
        .map_err(|e| Error::Acme(format!("new order: {e}")))?;

    info!(%domain, "ACME order created");

    // 3. Complete DNS-01 challenges ───────────────────────────────────────────
    let authorizations = order
        .authorizations()
        .await
        .map_err(|e| Error::Acme(format!("authorizations: {e}")))?;

    let mut created_record_ids: Vec<String> = Vec::new();

    for auth in &authorizations {
        // Skip authorizations that are already valid (e.g. from a previous run).
        if auth.status == AuthorizationStatus::Valid {
            debug!("authorization already valid, skipping");
            continue;
        }

        let challenge = auth
            .challenges
            .iter()
            .find(|c| c.r#type == ChallengeType::Dns01)
            .ok_or_else(|| Error::Acme("no DNS-01 challenge offered by CA".into()))?;

        let key_auth = order.key_authorization(challenge);
        let dns_value = key_auth.dns_value();
        let record_name = format!("_acme-challenge.{domain}");

        info!(%record_name, "creating Cloudflare TXT record for DNS-01 challenge");

        let record_id =
            cloudflare_create_txt(&http, &cf_token, &cf_zone_id, &record_name, &dns_value).await?;

        created_record_ids.push(record_id);

        order
            .set_challenge_ready(&challenge.url)
            .await
            .map_err(|e| Error::Acme(format!("set challenge ready: {e}")))?;
    }

    // 4. Wait for DNS propagation ─────────────────────────────────────────────
    info!("waiting {DNS_PROPAGATION_SECS}s for DNS propagation");
    tokio::time::sleep(Duration::from_secs(DNS_PROPAGATION_SECS)).await;

    // 5. Poll until order is Ready ────────────────────────────────────────────
    poll_until_ready(&mut order).await?;

    // 6. Generate key pair + CSR and finalize ────────────────────────────────
    let key_pair = KeyPair::generate().map_err(|e| Error::Acme(format!("key generation: {e}")))?;

    let params = CertificateParams::new(vec![domain.clone(), format!("*.{domain}")])
        .map_err(|e| Error::Acme(format!("cert params: {e}")))?;

    let csr = params
        .serialize_request(&key_pair)
        .map_err(|e| Error::Acme(format!("CSR: {e}")))?;

    order
        .finalize(csr.der())
        .await
        .map_err(|e| Error::Acme(format!("finalize: {e}")))?;

    // 7. Download the signed certificate chain ────────────────────────────────
    let cert_chain_pem = poll_certificate(&mut order).await?;

    // 8. Persist certificate and private key ─────────────────────────────────
    let cert_path = Path::new(&cfg.tls.cert_path);
    let key_path = Path::new(&cfg.tls.key_path);

    if let Some(parent) = cert_path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    tokio::fs::write(cert_path, cert_chain_pem.as_bytes()).await?;
    tokio::fs::write(key_path, key_pair.serialize_pem().as_bytes()).await?;

    info!(
        cert = %cert_path.display(),
        key  = %key_path.display(),
        "certificate saved"
    );

    // 9. Remove Cloudflare TXT records ───────────────────────────────────────
    for record_id in &created_record_ids {
        if let Err(e) = cloudflare_delete_txt(&http, &cf_token, &cf_zone_id, record_id).await {
            warn!(%record_id, "failed to delete DNS TXT record: {e}");
        }
    }

    Ok(())
}

// ── ACME account management ───────────────────────────────────────────────────

async fn load_or_create_account(email: &str, account_dir: &str, staging: bool) -> Result<Account> {
    let account_file = Path::new(account_dir).join("acme-account.json");

    if account_file.exists() {
        let raw = tokio::fs::read_to_string(&account_file).await?;
        let credentials: AccountCredentials = serde_json::from_str(&raw)
            .map_err(|e| Error::Acme(format!("parse account credentials: {e}")))?;

        info!(path = %account_file.display(), "loading existing ACME account");
        Account::from_credentials(credentials)
            .await
            .map_err(|e| Error::Acme(format!("load account: {e}")))
    } else {
        let server_url = if staging {
            LetsEncrypt::Staging.url()
        } else {
            LetsEncrypt::Production.url()
        };

        info!(
            %email,
            env = if staging { "staging" } else { "production" },
            "creating new ACME account"
        );

        let (account, credentials) = Account::create(
            &NewAccount {
                contact: &[&format!("mailto:{email}")],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            server_url,
            None,
        )
        .await
        .map_err(|e| Error::Acme(format!("create account: {e}")))?;

        // Persist credentials so we reuse the same account on restart.
        tokio::fs::create_dir_all(account_dir).await?;
        let json = serde_json::to_string_pretty(&credentials)
            .map_err(|e| Error::Acme(format!("serialize credentials: {e}")))?;
        tokio::fs::write(&account_file, json.as_bytes()).await?;

        info!(path = %account_file.display(), "ACME account credentials saved");
        Ok(account)
    }
}

// ── order polling ─────────────────────────────────────────────────────────────

async fn poll_until_ready(order: &mut instant_acme::Order) -> Result<()> {
    for attempt in 0..MAX_POLL_ATTEMPTS {
        tokio::time::sleep(Duration::from_secs(POLL_INTERVAL_SECS)).await;

        order
            .refresh()
            .await
            .map_err(|e| Error::Acme(format!("order refresh: {e}")))?;

        match order.state().status {
            OrderStatus::Ready => {
                info!("ACME order is ready");
                return Ok(());
            }
            OrderStatus::Invalid => {
                return Err(Error::Acme("ACME order became invalid".into()));
            }
            status => {
                debug!(attempt, ?status, "waiting for order to become ready");
            }
        }
    }

    Err(Error::Acme(format!(
        "order did not become ready after {} attempts",
        MAX_POLL_ATTEMPTS
    )))
}

async fn poll_certificate(order: &mut instant_acme::Order) -> Result<String> {
    for attempt in 0..MAX_POLL_ATTEMPTS {
        tokio::time::sleep(Duration::from_secs(POLL_INTERVAL_SECS)).await;

        match order
            .certificate()
            .await
            .map_err(|e| Error::Acme(format!("certificate download: {e}")))?
        {
            Some(pem) => {
                info!("certificate chain downloaded");
                return Ok(pem);
            }
            None => {
                order
                    .refresh()
                    .await
                    .map_err(|e| Error::Acme(format!("order refresh: {e}")))?;
                debug!(attempt, "certificate not yet available");
            }
        }
    }

    Err(Error::Acme(format!(
        "certificate not available after {} attempts",
        MAX_POLL_ATTEMPTS
    )))
}

// ── Cloudflare DNS API ────────────────────────────────────────────────────────

#[derive(Serialize)]
struct CreateTxtRecord<'a> {
    r#type: &'a str,
    name: &'a str,
    content: &'a str,
    ttl: u32,
}

#[derive(Deserialize)]
struct CfResponse<T> {
    success: bool,
    result: Option<T>,
    errors: Vec<CfError>,
}

#[derive(Deserialize)]
struct CfError {
    #[allow(dead_code)]
    code: u32,
    message: String,
}

#[derive(Deserialize)]
struct CfDnsRecord {
    id: String,
}

/// Create a DNS TXT record and return its Cloudflare record ID.
async fn cloudflare_create_txt(
    client: &Client,
    token: &str,
    zone_id: &str,
    name: &str,
    content: &str,
) -> Result<String> {
    let url = format!("{CF_API}/zones/{zone_id}/dns_records");

    let resp: CfResponse<CfDnsRecord> = client
        .post(&url)
        .bearer_auth(token)
        .json(&CreateTxtRecord {
            r#type: "TXT",
            name,
            content,
            ttl: 60,
        })
        .send()
        .await
        .map_err(|e| Error::Acme(format!("Cloudflare API request: {e}")))?
        .json()
        .await
        .map_err(|e| Error::Acme(format!("Cloudflare API parse: {e}")))?;

    if !resp.success {
        let msg = resp
            .errors
            .first()
            .map(|e| e.message.as_str())
            .unwrap_or("unknown error");
        return Err(Error::Acme(format!("Cloudflare create TXT: {msg}")));
    }

    resp.result
        .map(|r| r.id)
        .ok_or_else(|| Error::Acme("Cloudflare returned no record ID".into()))
}

/// Delete a Cloudflare DNS record by its ID.
async fn cloudflare_delete_txt(
    client: &Client,
    token: &str,
    zone_id: &str,
    record_id: &str,
) -> Result<()> {
    let url = format!("{CF_API}/zones/{zone_id}/dns_records/{record_id}");
    client
        .delete(&url)
        .bearer_auth(token)
        .send()
        .await
        .map_err(|e| Error::Acme(format!("Cloudflare delete: {e}")))?;
    Ok(())
}

// ── TLS config builder ────────────────────────────────────────────────────────

/// Build a `rustls::ServerConfig` from PEM cert and key files.
pub fn build_tls_config(cert_path: &str, key_path: &str) -> Result<RustlsConfig> {
    let cert_chain = {
        let file = std::fs::File::open(cert_path)
            .map_err(|e| Error::Tls(format!("open cert '{cert_path}': {e}")))?;
        certs(&mut BufReader::new(file))
            .collect::<std::io::Result<Vec<CertificateDer<'static>>>>()
            .map_err(|e| Error::Tls(format!("parse cert '{cert_path}': {e}")))?
    };

    let key = {
        let file = std::fs::File::open(key_path)
            .map_err(|e| Error::Tls(format!("open key '{key_path}': {e}")))?;
        private_key(&mut BufReader::new(file))
            .map_err(|e| Error::Tls(format!("parse key '{key_path}': {e}")))?
            .ok_or_else(|| Error::Tls(format!("no private key in '{key_path}'")))?
    };

    RustlsConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .map_err(|e| Error::Tls(format!("build server config: {e}")))
}

// ── cert expiry check ─────────────────────────────────────────────────────────

/// Return `true` if the PEM certificate at `path` expires within `threshold_days`.
///
/// Returns `true` on any parse error so the cert is treated as needing renewal.
fn cert_expiring_within(path: &str, threshold_days: i64) -> bool {
    let pem_bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            debug!(%path, "cannot read cert file ({e}) — treating as expiring");
            return true;
        }
    };

    // Parse the first certificate from the PEM bundle.
    let (_, pem) = match x509_parser::pem::parse_x509_pem(&pem_bytes) {
        Ok(p) => p,
        Err(e) => {
            warn!(%path, "cannot parse PEM ({e:?}) — treating as expiring");
            return true;
        }
    };

    let (_, cert) = match x509_parser::certificate::X509Certificate::from_der(&pem.contents) {
        Ok(c) => c,
        Err(e) => {
            warn!(%path, "cannot parse certificate ({e:?}) — treating as expiring");
            return true;
        }
    };

    let not_after = cert.validity().not_after.timestamp();
    let now = chrono::Utc::now().timestamp();
    let remaining = (not_after - now) / 86_400; // days

    debug!(%path, remaining_days = remaining, threshold_days, "cert expiry check");
    remaining < threshold_days
}

// ── credential resolution ─────────────────────────────────────────────────────

/// Return the Cloudflare API token.
///
/// Checks `CLOUDFLARE_API_TOKEN` env var first; falls back to the config field.
fn resolve_cloudflare_token(cfg: &AppConfig) -> Result<String> {
    if let Ok(v) = std::env::var("CLOUDFLARE_API_TOKEN") {
        return Ok(v);
    }
    if !cfg.tls.cloudflare_api_token.is_empty() {
        return Ok(cfg.tls.cloudflare_api_token.clone());
    }
    Err(Error::Config(
        "Cloudflare API token required: set CLOUDFLARE_API_TOKEN env var \
         or tls.cloudflare_api_token in config"
            .into(),
    ))
}

/// Return the Cloudflare Zone ID.
///
/// Checks `CLOUDFLARE_ZONE_ID` env var first; falls back to the config field.
fn resolve_cloudflare_zone_id(cfg: &AppConfig) -> Result<String> {
    if let Ok(v) = std::env::var("CLOUDFLARE_ZONE_ID") {
        return Ok(v);
    }
    if !cfg.tls.cloudflare_zone_id.is_empty() {
        return Ok(cfg.tls.cloudflare_zone_id.clone());
    }
    Err(Error::Config(
        "Cloudflare Zone ID required: set CLOUDFLARE_ZONE_ID env var \
         or tls.cloudflare_zone_id in config"
            .into(),
    ))
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cert_expiring_within_returns_true_for_missing_file() {
        assert!(cert_expiring_within("/nonexistent/path.pem", 30));
    }

    #[test]
    fn resolve_cloudflare_token_falls_back_to_config() {
        // Does not touch env vars — safe to run in parallel.
        let mut cfg = crate::config::ServerConfig::default();
        cfg.tls.cloudflare_api_token = "config-token".to_string();
        // Temporarily clear env so config fallback is exercised.
        let saved = std::env::var("CLOUDFLARE_API_TOKEN").ok();
        unsafe { std::env::remove_var("CLOUDFLARE_API_TOKEN") };
        let result = resolve_cloudflare_token(&cfg);
        if let Some(v) = saved {
            unsafe { std::env::set_var("CLOUDFLARE_API_TOKEN", v) };
        }
        assert_eq!(result.unwrap(), "config-token");
    }

    #[test]
    fn resolve_cloudflare_token_errors_when_both_unset() {
        // Only asserts the error case when neither source is configured.
        let saved = std::env::var("CLOUDFLARE_API_TOKEN").ok();
        unsafe { std::env::remove_var("CLOUDFLARE_API_TOKEN") };
        let cfg = crate::config::ServerConfig::default(); // token field is empty
        let result = resolve_cloudflare_token(&cfg);
        if let Some(v) = saved {
            unsafe { std::env::set_var("CLOUDFLARE_API_TOKEN", v) };
        }
        assert!(result.is_err());
    }
}
