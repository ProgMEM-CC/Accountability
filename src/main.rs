//! Discord bot entry point – wires up Poise + serenity, registers the
//! `/request` slash command globally, and replies to each invocation
//! with an embed showing the username and session token.
//!
//! Configuration is read from `main.env` in the working directory
//! (clone `main.env.example` → `main.env` and fill in the values):
//!   - `DISCORD_TOKEN`    Bot account token.
//!   - `DISCORD_APP_ID`   Application ID (printed by the bot on startup
//!                        for debugging; poise uses it implicitly via
//!                        the gateway).
//!   - `PROXY_URL`        Optional. SOCKS5/HTTP proxy for miniblox.io.
//!   - `PROXY_POOL`       Optional. Comma-separated proxy pool.
//!
//! Slash contract:
//!   /request            – random username, one attempt.
//!   /request <Username> – explicitly named account.

mod hash;
mod log;
mod miniblox;
mod username;

use anyhow::{Context, Result};
use poise::serenity_prelude as serenity;
use std::env;

struct Data {}

type Error = anyhow::Error;
// Note: name is `BotCtx` rather than `Context` to avoid shadowing
// `anyhow::Context` -- the trait needs to stay in scope for `.context()`
// calls on `Result`s below.
type BotCtx<'a> = poise::Context<'a, Data, Error>;

/* ───────────────────────────  Slash-command arg parsing  ─────────────────────────── */

/// Number of POST attempts `/request` makes before giving up on a single
/// invocation. Fixed at three: 1 initial + 2 retries. A retry budget
/// override is no longer exposed on the slash command -- three attempts
/// is plenty for the most common failure mode (409 nonce rejection, see
/// `is_retryable_status`) and keeps the interaction well within
/// Discord's deferred-reply window.
const TOTAL_ATTEMPTS: u32 = 3;

/// Cap on how many 429 back-off retries a single `/request` invocation
/// is allowed to issue *in total* (across all attempt slots). 429 means
/// "Too Many Requests" -- the server is asking us to slow down, NOT
/// telling us our payload is broken. We sleep exponentially
/// (1s, 2s, 4s, 8s, 16s) and re-POST the same body at the same attempt
/// slot *without* incrementing [`TOTAL_ATTEMPTS`] (the request counter
/// is preserved so the user still sees e.g. "1 / 3" in the embed).
///
/// Five back-offs max out at 31 cumulative seconds of waiting once
/// you've added them up, which keeps a persistently throttled IP from
/// looping the slash command indefinitely. After the cap, we report
/// the failure with the embed explaining that the IP is rate-limited.
const MAX_RATE_LIMIT_BACKOFFS: u32 = 5;

/// Whether a non-OK HTTP status code is worth retrying under the loop in
/// `request()`. Transport errors (`status == 0`) and 5xx server errors
/// are transient by nature; the retryable 4xx subset is the
/// "back off and try again" codes per RFC 7231 -- `408 Request Timeout`
/// and `429 Too Many Requests` -- plus `409 Conflict`, which miniblox
/// appears to emit when the body it received doesn't have a valid-looking
/// nonce. Because every retry runs through `miniblox::next_nonce(attempt)`
/// (and so generates a *fresh* hash), retrying a 409 has a real chance
/// of succeeding on attempt N+1. The remaining 4xx codes (400, 401, 403,
/// 404, 410, 451, ...) are deterministic against the same request body
/// and won't change on a second attempt, so we don't waste budget on
/// them.
fn is_retryable_status(status: u16) -> bool {
    status == 0 || status >= 500 || status == 408 || status == 409 || status == 429
}

/* ───────────────────────────  /request command  ─────────────────────────── */

/// Generate a miniblox.io guest account and return the session token.
///
/// Slash-command contract:
///   * `/request`             -- random username.
///   * `/request <Username>`  -- explicitly named account.
///
/// The command always retries up to [`TOTAL_ATTEMPTS`] times before
/// reporting failure. Each attempt produces a fresh nonce
/// (`miniblox::next_nonce(attempt)`), and when no username is supplied
/// the random username is also rolled fresh per attempt so we don't
/// just retry the exact same body that already failed. The headline
/// reason the retry budget matters: miniblox.io rejects many requests
/// with `409 Conflict` when the body's nonce doesn't look right;
/// rolling a new nonce per attempt gives the next POST a real chance
/// of being accepted.
#[poise::command(slash_command)]
async fn request(
    ctx: BotCtx<'_>,
    #[description = "Username (leave empty for a random one)"]
    username: Option<String>,

    #[description = "Skin (leave empty for default skin Bob)"]
    skin: Option<String>,
) -> Result<(), Error> {
    if let Err(e) = ctx.defer().await {
        log::error("commands::request", &format!("could not defer reply: {e}"));
        return Err(e.into());
    }

    let username_override = username.as_deref();
    let max_retries = TOTAL_ATTEMPTS;

    log::info(
        "commands::request",
        &format!(
            "received /request (username={}, skin={}, max_retries={})",
            username_override.unwrap_or("(random)"),
            skin.as_deref().unwrap_or("(default)"),
            max_retries,
        ),
    );

    // Resolve the proxy pool ONCE per `/request` invocation. We
    // rotate through it across the 3 outer attempt slots -- attempt 1
    // uses entry 0, attempt 2 uses entry 1, attempt 3 uses entry 2 (or
    // wraps modulo len). When every provider's scraper panicked/timed
    // out the pool is empty and we fall back to a direct connection
    // for `--all 3` outer attempt slots.
    let proxy_pool = miniblox::resolve_proxy_pool().await;
    log::info(
        "commands::request",
        &format!(
            "resolved proxy pool: {} entries; rotating 1 per outer attempt, reusing during in-slot 429 back-offs",
            proxy_pool.len(),
        ),
    );

    // Track the most recent outcome so we can show it if we exhaust the
    // budget. `succeeded_attempt` is only meaningful when `last_outcome`
    // is `Ok`. `last_attempt` is the 1-based attempt number of the last
    // *outer* iteration we ran -- it is what the failure embed labels
    // "X / N attempts" so the user sees e.g. "1 / 3" after we've burned
    // several 429 back-off retries. `rate_limit_retries` is the count
    // of 429 back-offs across this whole invocation, capped by
    // [`MAX_RATE_LIMIT_BACKOFFS`].
    let mut last_outcome: Option<miniblox::AttemptOutcome> = None;
    let mut succeeded_attempt: u32 = 0;
    let mut last_attempt: u32 = 0;
    let mut rate_limit_retries: u32 = 0;

    // 'outer iterates the 3-slot POST budget. 'inner handles 429
    // rate-limit back-offs within a single outer slot -- a 429 hit
    // sleeps (1s, 2s, 4s, 8s, 16s) and re-POSTs the same body at
    // the *same* attempt number without advancing our outer counter.
    // Any non-429 status breaks 'inner and falls through to the next
    // 'outer iteration (subject to the usual retry-or-stop logic below).
    'outer: for attempt in 1..=max_retries {
        // Pick a (possibly different) proxy per outer attempt. The
        // rotation means attempt 1 uses `proxy_pool[0]`, attempt 2
        // uses `proxy_pool[1]`, attempt 3 uses `proxy_pool[2]` (or
        // wraps modulo len). This avoids looping back into the same
        // rate-limited IP slot. 429 *back-offs* inside one outer slot
        // reuse the same proxy so we don't pay the construction cost
        // on every back-off and don't shuffle away from a proxy that
        // might recover.
        let proxy = if proxy_pool.is_empty() {
            None
        } else {
            Some(proxy_pool[(attempt - 1) as usize % proxy_pool.len()].clone())
        };
        let client = match miniblox::build_http_client(proxy) {
            Ok(c) => c,
            Err(e) => {
                log::error(
                    "commands::request",
                    &format!(
                        "could not build HTTP client on attempt {attempt}/{max_retries}: {e}"
                    ),
                );
                reply_error(&ctx, "could not build HTTP client", &e.to_string()).await?;
                return Ok(());
            }
        };

        let nonce = miniblox::next_nonce(attempt as u64);

        'inner: loop {
            let outcome = miniblox::attempt_create_account(
                username_override,
                skin.as_deref(),
                &nonce,
                &client,
            )
            .await;
            last_attempt = attempt;

            match &outcome {
                miniblox::AttemptOutcome::Ok(_) => {
                    log::info(
                        "commands::request",
                        &format!(
                            "succeeded on attempt {attempt}/{max_retries} (nonce={nonce})"
                        ),
                    );
                    succeeded_attempt = attempt;
                    // Clone out of `&outcome`: the match arm's borrow
                    // is still live when surrounding log formatting
                    // finishes, and we want `last_outcome` to survive
                    // the eventual `break`.
                    last_outcome = Some(outcome.clone());
                    break 'outer;
                }
                miniblox::AttemptOutcome::Err { status, body, .. } => {
                    let s = *status;
                    let truncated = truncate(body, 200);

                    // 429 is "Too Many Requests". The server is
                    // asking us to slow down, NOT telling us our
                    // payload is broken. Sleep exponentially and
                    // re-POST the *same* body at the *same* attempt
                    // slot -- the outer counter is preserved. Cap the
                    // back-offs so a persistently throttled IP can't
                    // loop the slash command indefinitely.
                    if s == 429 {
                        rate_limit_retries += 1;
                        if rate_limit_retries > MAX_RATE_LIMIT_BACKOFFS {
                            log::warn(
                                "commands::request",
                                &format!(
                                    "rate-limited {rate_limit_retries} times across this /request; giving up"
                                ),
                            );
                            last_outcome = Some(outcome.clone());
                            break 'outer;
                        }
                        // Exponential back-off: 1, 2, 4, 8, 16 seconds.
                        let exp = (rate_limit_retries - 1).min(4);
                        let delay_secs: u64 = 1u64 << exp;
                        log::warn(
                            "commands::request",
                            &format!(
                                "429 Too Many Requests on attempt {attempt}/{max_retries}: backing off {delay_secs}s before retrying same attempt ({rate_limit_retries}/{MAX_RATE_LIMIT_BACKOFFS})"
                            ),
                        );
                        tokio::time::sleep(std::time::Duration::from_secs(
                            delay_secs,
                        ))
                        .await;
                        continue 'inner;
                    }

                    let retryable = is_retryable_status(s);
                    log::warn(
                        "commands::request",
                        &format!(
                            "attempt {attempt}/{max_retries} failed (status={s}, retryable={retryable}): {truncated}"
                        ),
                    );
                    last_outcome = Some(outcome.clone());

                    if !retryable {
                        log::warn(
                            "commands::request",
                            &format!(
                                "stopping after attempt {attempt}/{max_retries}: non-retryable status {s}"
                            ),
                        );
                        break 'outer;
                    }
                    if attempt == max_retries {
                        log::warn(
                            "commands::request",
                            &format!(
                                "stopping after attempt {attempt}/{max_retries}: retry budget exhausted"
                            ),
                        );
                        break 'outer;
                    }
                    break 'inner;
                }
            }
        }
    }

    match last_outcome {
        Some(miniblox::AttemptOutcome::Ok(result)) => {
            reply_success(&ctx, &result, succeeded_attempt, max_retries).await?;
        }
        Some(miniblox::AttemptOutcome::Err {
            username,
            nonce,
            status,
            body,
        }) => {
            reply_failure(&ctx, &username, &nonce, status, &body, last_attempt, max_retries)
                .await?;
        }
        None => {
            // Defensive: the loop above always runs at least once and
            // always assigns `last_outcome` before reaching the break,
            // so this branch should be unreachable.
            reply_error(
                &ctx,
                "internal error",
                "no attempt outcome was recorded (loop invariant broken)",
            )
            .await?;
        }
    }

    Ok(())
}

async fn reply_success(
    ctx: &BotCtx<'_>,
    result: &miniblox::AccountResult,
    attempt: u32,
    max_attempts: u32,
) -> Result<()> {
    let embed = serenity::CreateEmbed::new()
        .title("🎮 Miniblox Account Generated")
        .description(format!(
            "Here's your freshly minted **miniblox.io** guest account."
        ))
        .color(0x57_F2_87)
        .field(
            "Username",
            format!("`{}`", result.username),
            false,
        )
        .field(
            "Session Token",
            format!("```\n{}\n```", truncate(&result.session_token, 1900)),
            false,
        )
        .field(
            "Nonce",
            format!("`{}`", result.nonce),
            true,
        )
        .field(
            "Attempt",
            format!("`{} / {}`", attempt, max_attempts),
            true,
        )
        .field(
            "HTTP",
            format!("`{}`", result.status),
            true,
        )
        .footer(serenity::CreateEmbedFooter::new(
            "Requested via /request -- keep your token private.",
        ))
        .timestamp(serenity::Timestamp::now());

    let reply = poise::CreateReply::default()
        .embed(embed)
        .ephemeral(true); // tokens shouldn't stay in chat history
    ctx.send(reply).await.context("failed to send success reply")?;
    Ok(())
}

async fn reply_failure(
    ctx: &BotCtx<'_>,
    username: &str,
    nonce: &str,
    status: u16,
    body: &str,
    attempts_made: u32,
    max_attempts: u32,
) -> Result<()> {
    // 409 in particular gets a custom label because miniblox.io
    // appears to return it when the body's nonce doesn't pass its
    // server-side validity check -- *not* because of a username clash.
    // Calling it "conflict / rate-limited" hides the actual cause and
    // misleads the user. We now surface the likely cause in plain text
    // so the user understands why it failed and what to do next.
    let (status_label, color, cause_hint) = match status {
        0 => (
            "Transport error".to_owned(),
            0xED_42_45_u32,
            "couldn't reach miniblox.io at all -- check your network or proxy pool.".to_owned(),
        ),
        409 => (
            "409 Conflict (likely nonce rejected)".to_owned(),
            0xED_42_45_u32,
            "miniblox.io didn't accept the nonce on any of the attempts; this is usually transient, so try /request again -- each invocation rolls a fresh nonce.".to_owned(),
        ),
        429 => (
            "429 Too Many Requests (rate-limited)".to_owned(),
            0xED_42_45_u32,
            "miniblox.io is rate-limiting our IP. We retried the same body with exponential back-off (1s -> 2s -> 4s -> 8s -> 16s, up to 5 retries) but the throttle never lifted -- try again in a minute or via a different proxy.".to_owned(),
        ),
        code if code >= 500 => (
            format!("Server error {code}"),
            0xED_42_45_u32,
            "miniblox.io is having a bad time. Try /request again in a few seconds.".to_owned(),
        ),
        code => (
            format!("HTTP {code}"),
            0xFE_B7_40_u32,
            format!(
                "Status {code} is deterministic against the same request body, so a retry with the same body won't help -- the payload itself is wrong."
            ),
        ),
    };

    let burnt_full_budget = attempts_made == max_attempts;
    let attempts_noun = if attempts_made == 1 {
        "attempt"
    } else {
        "attempts"
    };
    let stopped_early_note = if !burnt_full_budget {
        "\nStopped early because this status code is non-retryable, even though the budget had more attempts left."
    } else {
        ""
    };

    let description = format!(
        "miniblox.io rejected the request with **{status_label}** after **{attempts_made} / {max_attempts}** {attempts_noun}.\n{cause_hint}{stopped_early_note}",
    );

    let embed = serenity::CreateEmbed::new()
        .title("❌ Account creation failed")
        .description(description)
        .color(color)
        .field(
            "Username",
            format!("`{}`", username),
            false,
        )
        .field(
            "Nonce",
            format!("`{}`", nonce),
            true,
        )
        .field(
            "Attempts",
            format!("`{} / {}`", attempts_made, max_attempts),
            true,
        )
        .field(
            "Server response",
            format!("```\n{}\n```", truncate(body, 900)),
            false,
        )
        .footer(serenity::CreateEmbedFooter::new(
            "Try /request again -- each /request rotates the nonce (and proxy).",
        ))
        .timestamp(serenity::Timestamp::now());

    ctx.send(poise::CreateReply::default().embed(embed).ephemeral(true))
        .await
        .context("failed to send failure reply")?;
    Ok(())
}

async fn reply_error(ctx: &BotCtx<'_>, title: &str, detail: &str) -> Result<()> {
    let embed = serenity::CreateEmbed::new()
        .title(format!("⚠️ {title}"))
        .description(truncate(detail, 1900))
        .color(0xED_42_45);
    ctx.send(poise::CreateReply::default().embed(embed).ephemeral(true))
        .await
        .context("failed to send error reply")?;
    Ok(())
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_owned();
    }
    let truncated: String = s.chars().take(max).collect();
    format!("{truncated}\n…(truncated)")
}

/* ───────────────────────────  Bot bootstrap  ─────────────────────────── */

#[tokio::main]
async fn main() -> Result<()> {
    // 1. Load configuration. We support both `main.env` (project default)
    //    and the user's shell environment. The dotenvy loader skips
    //    already-set values, so a real CI/CD deploy doesn't need a file.
    let env_path = std::path::Path::new("main.env");
    if env_path.exists() {
        dotenvy::from_filename(env_path)
            .context("could not read main.env — copy main.env.example to main.env and fill it in")?;
        log::info("startup", "loaded main.env");
    } else {
        log::warn(
            "startup",
            "main.env not present in CWD; falling back to process environment",
        );
    }

    let token = env::var("DISCORD_TOKEN").context("DISCORD_TOKEN missing from main.env")?;
    let app_id = env::var("DISCORD_APP_ID").unwrap_or_else(|_| String::from("(unset)"));

    log::info("startup", &format!("logging in (app id {app_id})"));

    let intents = serenity::GatewayIntents::non_privileged();

    let framework = poise::Framework::builder()
        .setup(move |ctx, _ready, framework| {
            let app_id = app_id.clone();
            Box::pin(async move {
                poise::builtins::register_globally(ctx, &framework.options().commands)
                    .await
                    .context("failed to register /request with Discord")?;
                log::info(
                    "startup",
                    &format!(
                        "/request registered globally for app {app_id}. Use it in any server the bot is in.",
                    ),
                );
                Ok(Data {})
            })
        })
        .options(poise::FrameworkOptions {
            commands: vec![request()],
            prefix_options: poise::PrefixFrameworkOptions {
                prefix: None, // slash-command only
                ..Default::default()
            },
            ..Default::default()
        })
        .build();

    let mut client = serenity::ClientBuilder::new(token, intents)
        .framework(framework)
        .await
        .context("failed to build the Discord client (check DISCORD_TOKEN)")?;

    log::info("startup", "Discord client connected – listening for /request.");
    client.start().await.context("Discord gateway crashed")?;
    Ok(())
}

/* ───────────────────────────  Tests  ─────────────────────────── */

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_retryable_status_table() {
        // Retryable set: transport errors, 5xx, and the four 4xx codes
        // that *can* succeed on a different attempt:
        //   * 408 Request Timeout       -- read timeout, retry.
        //   * 409 Conflict              -- in miniblox's case the body
        //     nonce didn't pass server-side validation; retrying
        //     with a fresh nonce via `next_nonce(attempt)` has a real
        //     chance of succeeding.
        //   * 429 Too Many Requests     -- back off + retry.
        for s in [0u16, 408, 409, 429, 500, 502, 503, 504, 599] {
            assert!(is_retryable_status(s), "expected {s} to be retryable");
        }
        // All other 4xx (and by extension, 1xx/2xx/3xx) are non-retryable.
        for s in [200u16, 201, 204, 400, 401, 403, 404, 410, 418, 451] {
            assert!(
                !is_retryable_status(s),
                "expected {s} to be non-retryable"
            );
        }
    }
}
