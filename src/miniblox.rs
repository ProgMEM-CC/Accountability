//! Miniblox.io guest-account generator.
//!
//! Verbatim port of the request shape from `AccGen/lib/miniblox.ts`:
//!
//! ```text
//! POST https://miniblox.io/auth-api/accounts/guest
//! headers: Accept, Content-Type, Referer (https://miniblox.io/)
//! body:    { username, skin: "Bob", nonce, ctree: 0.5 }
//! ```
//!
//! The `nonce` is a 128-bit FingerprintJS `x64hash128` derived from
//! per-call CSPRNG entropy interleaved with a counter – see `nextNonce`.
//! miniblox rejects responses that don't match the FPJS byte order, so
//! the hashing module is the load-bearing piece of this port.

use crate::hash::x64hash128;
use crate::log;
use crate::username::generate_username;
use anyhow::{Context, Result};
use rand::RngCore;
use serde::Deserialize;
use serde_json::json;

const MINIBLOX_URL: &str = "https://miniblox.io/auth-api/accounts/guest";
const DEFAULT_SKIN: &str = "Bob";
const NONCE_INPUT_BYTES: usize = 16;

/* ───────────────────────────  Nonce  ─────────────────────────── */

/// 32-char hex nonce – thin wrapper over [`next_nonce`] for call sites
/// that don't track an attempt counter.
pub fn generate_nonce() -> String {
    next_nonce(0)
}

/// Counter-aware variant. The counter is mixed into the seed string so
/// successive calls always produce a distinct hash – even in the
/// (vanishingly unlikely) case the CSPRNG bytes happen to repeat.
pub fn next_nonce(counter: u64) -> String {
    let mut buf = [0u8; NONCE_INPUT_BYTES];
    rand::thread_rng().fill_bytes(&mut buf);
    let hex: String = buf.iter().map(|b| format!("{b:02x}")).collect();
    x64hash128(&format!("{counter}:{hex}"), None)
}

/* ───────────────────────────  Response shape  ─────────────────────────── */

#[derive(Debug, Deserialize)]
struct MinibloxResponse {
    /// Common candidate field names. Some endpoints use `sessionToken`,
    /// others use `token` or `id`. We extract the first hit.
    #[serde(alias = "sessionToken", alias = "session_token", alias = "session", alias = "id")]
    session_token: Option<String>,
    /// Some endpoints don't ship a token in the body — fall back to dumping
    /// the response as a string so the user can still see it.
    #[serde(default)]
    raw: String,
}

#[derive(Debug, Clone)]
pub struct AccountResult {
    pub username: String,
    pub nonce: String,
    pub session_token: String,
    /// Raw success body for logging (so the user sees ANY fields the server
    /// returned alongside the token).
    pub raw_body: String,
    /// HTTP status for logging.
    pub status: u16,
}

#[derive(Debug, Clone)]
pub enum AttemptOutcome {
    Ok(AccountResult),
    Err {
        username: String,
        nonce: String,
        status: u16,
        body: String,
    },
}

/* ───────────────────────────  Proxy pool  ─────────────────────────── */

/// Resolve the proxy pool to use for an invocation. Returns the list of
/// proxies we rotate across the 3 outer attempt slots; an empty Vec
/// means "fall back to a direct connection for every attempt".
///
/// Resolution order:
///   1. `PROXY_URL` env var  -- a single URL.
///   2. `PROXY_POOL` env var -- comma-separated list.
///   3. [`collect_proxies`]  -- parallel scrape of the three
///      pxscrape-{sand, urban, browsec} providers, each in its own
///      panic-safe spawned task.
pub async fn resolve_proxy_pool() -> Vec<reqwest::Proxy> {
    if let Ok(url) = std::env::var("PROXY_URL") {
        let url = url.trim();
        if !url.is_empty() {
            return match reqwest::Proxy::all(url) {
                Ok(p) => vec![p],
                Err(e) => {
                    log::warn(
                        "proxy",
                        &format!("PROXY_URL is invalid: {e} -- using direct connection"),
                    );
                    Vec::new()
                }
            };
        }
    }
    if let Ok(pool) = std::env::var("PROXY_POOL") {
        let mut out = Vec::new();
        for entry in pool.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            match reqwest::Proxy::all(entry) {
                Ok(p) => out.push(p),
                Err(e) => log::warn(
                    "proxy",
                    &format!("skipped invalid PROXY_POOL entry {entry:?}: {e}"),
                ),
            }
        }
        if !out.is_empty() {
            return out;
        }
    }
    collect_proxies().await
}

/// Build a `reqwest::Client` with the (optional) proxy supplied by the
/// caller. `None` means "direct connection".
///
/// We build a fresh client per outer attempt in `request()` so the
/// proxy rotates across attempts AND a misbehaving proxy doesn't
/// poison later attempt slots. `reqwest::Client` construction is
/// cheap; the cost is dominated by the actual POSTs.
pub fn build_http_client(proxy: Option<reqwest::Proxy>) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .user_agent("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36")
        .timeout(std::time::Duration::from_secs(20));
    if let Some(p) = proxy {
        builder = builder.proxy(p);
    }
    builder.build().context("failed to build reqwest client")
}

/* ──────────────────  pxscrape provider pool (parallel, panic-safe)  ────────────────── */

/// Scrape the three pxscrape-{sand, urban, browsec} providers in
/// parallel and merge the workers' working proxies into a single Vec.
/// Each provider runs in its own spawned task; tokio catches any
/// panic inside the provider (e.g. `pxscrape-conglomerate`'s
/// `browsec.rs:9` `Result::unwrap()` on a Decode error) and turns it
/// into a `JoinError`, which we treat as "this provider contributed
/// nothing".
///
/// We deliberately do NOT use `pxscrape-conglomerate::get_proxies()`
/// because that function awaits sand -> urban -> browsec SEQUENTIALLY
/// and any panic in one provider unwinds the entire function, losing
/// the other two providers' contributions; isolating each provider
/// in its own tokio task is what keeps a single bad provider from
/// blocking the whole pool AND lets sandbox/urban proxies survive a
/// browsec upstream outage.
#[cfg(feature = "pxscrape-conglomerate")]
pub async fn collect_proxies() -> Vec<reqwest::Proxy> {
    let sand_handle = tokio::spawn(scrape_sand_safe());
    let urban_handle = tokio::spawn(scrape_urban_safe());
    let browsec_handle = tokio::spawn(scrape_browsec_safe());

    let sand = await_proxy_scrape(sand_handle, "sand").await;
    let urban = await_proxy_scrape(urban_handle, "urban").await;
    let browsec = await_proxy_scrape(browsec_handle, "browsec").await;

    log::info(
        "proxy",
        &format!(
            "pxscrape-conglomerate pool: sand={}, urban={}, browsec={} (total={})",
            sand.len(),
            urban.len(),
            browsec.len(),
            sand.len() + urban.len() + browsec.len(),
        ),
    );

    let mut out = Vec::with_capacity(sand.len() + urban.len() + browsec.len());
    out.extend(sand);
    out.extend(urban);
    out.extend(browsec);
    out
}

#[cfg(not(feature = "pxscrape-conglomerate"))]
pub async fn collect_proxies() -> Vec<reqwest::Proxy> {
    Vec::new()
}

#[cfg(feature = "pxscrape-conglomerate")]
async fn await_proxy_scrape(
    handle: tokio::task::JoinHandle<Vec<reqwest::Proxy>>,
    source: &str,
) -> Vec<reqwest::Proxy> {
    match handle.await {
        Ok(v) => v,
        Err(e) if e.is_panic() => {
            log::error(
                "proxy",
                &format!("{source} scraper panicked: {e} -- treating as empty"),
            );
            Vec::new()
        }
        Err(e) => {
            log::error("proxy", &format!("{source} scraper task error: {e}"));
            Vec::new()
        }
    }
}

/// Sand: clean `Result<Vec<HTTPProxy>, reqwest::Error>` API; no in-
/// crate panic risk. We still wrap in spawn + timeout because the
/// upstream sand endpoint can stall.
///
/// **Cross-major-version caveat:** `pxscrape-sand` compiles against
/// `reqwest 0.13`, but our crate uses `reqwest 0.12`. The two
/// `reqwest::Error` types live in distinct crates, so `?` cannot
/// auto-convert between them. We tolerate errors by `match`-ing the
/// `Result` and returning an empty `Vec` on failure instead of
/// propagating the error.
#[cfg(feature = "pxscrape-conglomerate")]
async fn scrape_sand_safe() -> Vec<reqwest::Proxy> {
    const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

    let spawn_res = tokio::spawn(async move {
        tokio::time::timeout(TIMEOUT, async {
            // No `?` -- see the function-level comment for why.
            let raw: Vec<pxscrape_sand::HTTPProxy> =
                match pxscrape_sand::get_proxies().await {
                    Ok(v) => v,
                    Err(e) => {
                        log::warn("proxy", &format!("sand scrape failed: {e}"));
                        return Vec::new();
                    }
                };
            let mut out: Vec<reqwest::Proxy> = Vec::with_capacity(raw.len());
            for p in raw {
                // Skip paid/premium entries -- they require credentials
                // we don't have.
                if p.paid || p.premium {
                    continue;
                }
                let port: u16 = match p.port.parse() {
                    Ok(n) => n,
                    Err(_) => {
                        log::warn(
                            "proxy",
                            &format!("sand: dropping proxy {} -- bad port {:?}", p.host, p.port),
                        );
                        continue;
                    }
                };
                let url = format!(
                    "http://{}:{}@{}:{}",
                    p.username, p.password, p.host, port,
                );
                if let Ok(proxy) = reqwest::Proxy::all(&url) {
                    out.push(proxy);
                }
            }
            out
        })
        .await
    })
    .await;

    let timed = match spawn_res {
        Ok(r) => r,
        Err(e) if e.is_panic() => {
            log::error("proxy", &format!("sand scraper panicked: {e}"));
            return Vec::new();
        }
        Err(e) => {
            log::error("proxy", &format!("sand scraper task error: {e}"));
            return Vec::new();
        }
    };

    match timed {
        Ok(v) => v,
        Err(_) => {
            log::warn("proxy", "sand scrape timed out");
            Vec::new()
        }
    }
}

/// Urban: 4 sequential reqwest calls (anonymous registration -> security
/// token -> countries -> per-server auth proxy token). All steps
/// return `Result`, so there are no in-crate unwraps. A single
/// per-server token fetch failure is tolerated (we `continue` past
/// it) so one downed server doesn't drop the whole list.
///
/// **Cross-major-version caveat:** `pxscrape-urban` compiles against
/// `reqwest 0.13`, but our crate uses `reqwest 0.12`. The two
/// `reqwest::Error` types live in distinct crates, so `?` cannot
/// auto-convert between them. Each step is `match`-ed explicitly and
/// returns an empty `Vec` (instead of propagating the error) on
/// failure.
#[cfg(feature = "pxscrape-conglomerate")]
async fn scrape_urban_safe() -> Vec<reqwest::Proxy> {
    const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

    let spawn_res = tokio::spawn(async move {
        tokio::time::timeout(TIMEOUT, async {
            // No `?` anywhere in the body -- see the function-level
            // comment.

            let acc = match pxscrape_urban::AccountService::new()
                .register_anonymous()
                .await
            {
                Ok(r) => r.value,
                Err(e) => {
                    log::warn("proxy", &format!("urban register_anonymous failed: {e}"));
                    return Vec::new();
                }
            };
            let ss = pxscrape_urban::SecurityService::new();
            let st = match ss.get_security_token(&acc).await {
                Ok(t) => t.value,
                Err(e) => {
                    log::warn("proxy", &format!("urban get_security_token failed: {e}"));
                    return Vec::new();
                }
            };
            let sps = pxscrape_urban::StaticProxiesService::new(st.clone());
            let countries = match sps.get_countries().await {
                Ok(c) => c.elements,
                Err(e) => {
                    log::warn("proxy", &format!("urban get_countries failed: {e}"));
                    return Vec::new();
                }
            };

            let mut out: Vec<reqwest::Proxy> = Vec::new();
            for srv in countries
                .into_iter()
                .flat_map(|c| c.servers.elements)
                .flatten()
                .filter(|s| s.access_type != pxscrape_urban::AccessType::Inaccessible)
            {
                let primary = srv.address.primary;
                let signature = srv.signature;
                let apt = match ss.get_auth_proxy_token(&st, &signature).await {
                    Ok(t) => t.value,
                    Err(e) => {
                        log::warn(
                            "proxy",
                            &format!(
                                "urban per-server token failed for {}: {e} -- skipping this server",
                                primary.host
                            ),
                        );
                        continue;
                    }
                };
                let url = format!(
                    "http://{}:1@{}:{}",
                    apt, primary.host, primary.port,
                );
                if let Ok(proxy) = reqwest::Proxy::all(&url) {
                    out.push(proxy);
                }
            }
            out
        })
        .await
    })
    .await;

    let timed = match spawn_res {
        Ok(r) => r,
        Err(e) if e.is_panic() => {
            log::error("proxy", &format!("urban scraper panicked: {e}"));
            return Vec::new();
        }
        Err(e) => {
            log::error("proxy", &format!("urban scraper task error: {e}"));
            return Vec::new();
        }
    };

    match timed {
        Ok(v) => v,
        Err(_) => {
            log::warn("proxy", "urban scrape timed out");
            Vec::new()
        }
    }
}

/// Browsec: clean `Result<Servers, reqwest::Error>` API. The Decode
/// panic the user reported originally lives in
/// `pxscrape-conglomerate`'s `browsec.rs` (which `.unwrap()`s the
/// result) -- not in `pxscrape_browsec` itself. By calling the
/// underlying `get_servers()` from inside a panic-safe spawn, we
/// sidestep the upstream panic; if the body still has invalid JSON
/// the parse returns `reqwest::Error` instead of a worker-thread
/// panic and the scraper returns an empty Vec.
///
/// **Cross-major-version caveat:** `pxscrape-browsec` compiles against
/// `reqwest 0.13`, but our crate uses `reqwest 0.12`. The two
/// `reqwest::Error` types live in distinct crates, so `?` cannot
/// auto-convert between them. We `match` the `Result` explicitly and
/// return an empty `Vec` (instead of propagating the error) on
/// failure.
#[cfg(feature = "pxscrape-conglomerate")]
async fn scrape_browsec_safe() -> Vec<reqwest::Proxy> {
    const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

    let spawn_res = tokio::spawn(async move {
        tokio::time::timeout(TIMEOUT, async {
            // No `?` -- see the function-level comment.
            let servers = match pxscrape_browsec::get_servers().await {
                Ok(s) => s,
                Err(e) => {
                    log::warn("proxy", &format!("browsec get_servers failed: {e}"));
                    return Vec::new();
                }
            };
            let mut out: Vec<reqwest::Proxy> = Vec::new();
            for (_country_code, country_data) in servers.countries {
                let in_country = match country_data.servers {
                    Some(v) => v,
                    None => continue,
                };
                for s in in_country {
                    // Browsec exposes HTTPS endpoints without auth.
                    let url = format!("https://{}:{}", s.host, s.port);
                    if let Ok(proxy) = reqwest::Proxy::all(&url) {
                        out.push(proxy);
                    }
                }
            }
            out
        })
        .await
    })
    .await;

    let timed = match spawn_res {
        Ok(r) => r,
        Err(e) if e.is_panic() => {
            log::error("proxy", &format!("browsec scraper panicked: {e}"));
            return Vec::new();
        }
        Err(e) => {
            log::error("proxy", &format!("browsec scraper task error: {e}"));
            return Vec::new();
        }
    };

    match timed {
        Ok(v) => v,
        Err(_) => {
            log::warn("proxy", "browsec scrape timed out");
            Vec::new()
        }
    }
}

/// Make one POST to miniblox.io. Caller picks the username & nonce so
/// retries (counter-rotated nonces, fixed username) stay deterministic.
pub async fn attempt_create_account(
    username_override: Option<&str>,
    nonce: &str,
    client: &reqwest::Client,
) -> AttemptOutcome {
    let username = username_override
        .map(str::to_owned)
        .unwrap_or_else(|| generate_username(&mut rand::thread_rng()));

    let body = json!({
        "username": username,
        "skin": DEFAULT_SKIN,
        "nonce": nonce,
        "ctree": 0.5,
    });

    let resp = client
        .post(MINIBLOX_URL)
        .header("Accept", "application/json, text/plain, */*")
        .header("Content-Type", "application/json")
        .header("Referer", "https://miniblox.io/")
        .json(&body)
        .send()
        .await;

    let response = match resp {
        Ok(r) => r,
        Err(e) => {
            log::error(
                "miniblox",
                &format!("{} -> transport error: {e}", log::module_line("attempt", nonce, &username)),
            );
            return AttemptOutcome::Err {
                username,
                nonce: nonce.to_owned(),
                status: 0,
                body: e.to_string(),
            };
        }
    };

    let status = response.status().as_u16();
    let raw = response.text().await.unwrap_or_default();

    if !(200..300).contains(&status) {
        log::error(
            "generator",
            &format!(
                "{} Failed to generate account: Server(( {}, \"{}\", ), )",
                if nonce.is_empty() { String::new() } else { format!("{nonce} ") },
                status,
                extract_message(&raw).replace('\\', "\\\\").replace('"', "\\\""),
            ),
        );
        return AttemptOutcome::Err {
            username,
            nonce: nonce.to_owned(),
            status,
            body: raw,
        };
    }

    let token = parse_token(&raw).unwrap_or_else(|| raw.clone());
    log::info(
        "handlers::miniblox",
        &format!("{nonce} ({username}) generated."),
    );

    AttemptOutcome::Ok(AccountResult {
        username,
        nonce: nonce.to_owned(),
        session_token: token,
        raw_body: raw,
        status,
    })
}

fn parse_token(raw: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(raw).ok()?;
    for key in ["sessionToken", "session_token", "token", "id"] {
        if let Some(s) = v.get(key).and_then(|x| x.as_str()) {
            return Some(s.to_owned());
        }
    }
    None
}

fn extract_message(body: &str) -> String {
    let trimmed = body.trim();
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(trimmed) {
            if let Some(msg) = parsed.get("message").and_then(|x| x.as_str()) {
                return msg.to_owned();
            }
            if let Some(err) = parsed.get("error").and_then(|x| x.as_str()) {
                return err.to_owned();
            }
        }
    }
    trimmed.to_owned()
}

impl AccountResult {
    /// Convenience for the Discord bot – renders the result into an embed.
    pub fn token_display(&self) -> &str {
        &self.session_token
    }
}

/* ───────────────────────────  Tests  ─────────────────────────── */

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_shape_is_32_lowercase_hex() {
        for i in 0..20 {
            let n = next_nonce(i);
            assert_eq!(n.len(), 32, "nonce #{i} has wrong length");
            assert!(n.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        }
    }

    #[test]
    fn distinct_counters_give_distinct_hashes_even_with_fixed_bytes() {
        // Pin the random-bytes half of the seed string and only vary the
        // counter. If the COUNTER made it into x64hash128's input (it
        // does) the three hashes must differ — regardless of which byte
        // buffer we feed in.
        let fixed_bytes = [0xABu8; 16];
        let hex = fixed_bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let a = x64hash128(&format!("1:{hex}"), None);
        let b = x64hash128(&format!("2:{hex}"), None);
        let c = x64hash128(&format!("3:{hex}"), None);
        assert_ne!(a, b);
        assert_ne!(b, c);
        assert_ne!(a, c);
    }
}
