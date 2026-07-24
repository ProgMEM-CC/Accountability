# Miniblox AccGen Bot (Rust)

A Discord bot written in Rust that generates fresh miniblox.io guest
accounts on demand. Slash-command interface, embed-formatted response
with the **session token**, **username** and **nonce** in a clean
layout, optional VPN/proxy support.

This is a 1-to-1 Rust port of [`AccGen/`](./AccGen), the original TypeScript
Vercel-serverless generator. The hashing algorithm has been preserved
bit-for-bit so the nonces this bot emits still satisfy miniblox.io's
validators. The original log format, username dictionary, nonce layout
(`"<counter>:<hex-bytes>"` × `x64hash128`), and request body shape are
all kept verbatim.

---

## Quick start

```bash
# 1. Fill in secrets
cp main.env.example main.env
$EDITOR main.env          # set DISCORD_TOKEN, DISCORD_APP_ID

# 2. Build & run
cargo run --release
```

In Discord:

```
/request                   # random username (VectorAltBVJ / BobbyPin.dotted)
/request username: PixelAxe   # explicit username
```

The bot replies (ephemerally – the message only shows for you) with
an embed that contains:

- the **Username** it tried to register,
- the **Session Token** the server returned in a code block so it's
  easy to copy,
- the **Nonce** it sent (mirrors the JS `nextNonce()` output),
- the upstream **HTTP** status.

If the request fails (`409` rate-limit / `500` server error / etc.)
the bot sends a red embed with the server's response body and an
encouragement to retry – the nonce rotates per attempt, so retries
are always safe.

---

## Configuration (`main.env`)

| Variable          | Required | Notes                                                                  |
| :---------------- | :------: | :--------------------------------------------------------------------- |
| `DISCORD_TOKEN`   |    yes   | Bot account token from the Discord developer portal.                   |
| `DISCORD_APP_ID`  |    yes   | Application ID – logged on startup so you can confirm the right bot.  |
| `PROXY_URL`       |    no    | Single proxy (SOCKS5/HTTP) for all miniblox.io traffic.                |
| `PROXY_POOL`      |    no    | Comma-separated list; first non-empty entry is used.                   |

The VPN/proxy plumbing routes through the [`pxscrape-conglomerate`]
crate on crates.io. If that crate exposes any VPN-sourced proxy URL,
`resolve_proxy()` will pick it up automatically; otherwise the
explicit `PROXY_URL`/`PROXY_POOL` env vars take priority, and if
neither is set the bot talks to miniblox.io directly.

---

## Project layout

```
.
├── Cargo.toml
├── main.env.example        # Secret template – copy to main.env
├── rustfmt.toml
├── src/
│   ├── main.rs             # Bot entry, /request command, embeds
│   ├── hash.rs             # x64hash128 (FingerprintJS port)
│   ├── miniblox.rs         # Nonce, HTTP attempt, proxy plumbing
│   ├── username.rs         # Dictionary-based username generator
│   └── log.rs              # tracing-style logger
└── README.md
```

### Hashing algorithm

`src/hash.rs` ports [FingerprintJS's `x64hash128`](https://github.com/fingerprintjs/fingerprintjs/blob/master/src/utils/hashing.ts)
explicitly, including:

- the `[lo32, hi32]` storage layout (different from `mmh3.hash128`'s
  big-endian output),
- the 16-bit-limb carry chain for `x64_add`,
- the wider-than-u32 limb chain for `x64_multiply` (uses `u64` for the
  intermediate accumulators to avoid overflow that the JS version
  sidesteps by storing intermediates as IEEE-754 doubles),
- final output `h1.lo + h1.hi + h2.lo + h2.hi` (low half first).

The `#[cfg(test)] mod` block at the bottom of `src/hash.rs` matches
**every** FingerprintJS Jest vector verbatim. If a future edit moves
the byte order, that test catches it before a single line of code
hits production.

### Nonce shape

```rust
pub fn next_nonce(counter: u64) -> String {
    let mut buf = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut buf);
    let hex: String = buf.iter().map(|b| format!("{b:02x}")).collect();
    x64hash128(&format!("{counter}:{hex}"), None)
}
```

Same as `AccGen/lib/miniblox.ts`:

```ts
const bytes = randomBytes(16);
const hex   = bytes.map(b => b.toString(16).padStart(2, "0")).join("");
return x64hash128(`${counter}:${hex}`);
```

The counter prefix guarantees successive nonces are distinct even if
the CSPRNG bytes happened to repeat (defense in depth).

### Username dictionary

Same 29-word curated bank as the TS project, same `BobbyPin.mQaF`
dotted form (15 % probability) and `VectorAltBVJ` glued form (85 %).

### Logging

`src/log.rs` reproduces the TS `formatLog` with `padStart(5)` left
padding on the level field, so `INFO` becomes `" INFO "` (two spaces)
and `ERROR` stays as `"ERROR"` (one space). Timestamps are RFC-3339
UTC with 6 fractional digits, padded with `000` for fake-microsecond
precision – identical to the TS implementation.

---

## Related projects

- **`AccGen/`** – TypeScript Vercel-serverless generator (the project
  this one was ported from). Useful if you want the HTTP API form
  (`/api/generate`, `/api`) instead of the Discord bot.

---

## License

MIT.
