//! Tiny `tracing`-style logger. Mirrors `AccGen/lib/log.ts`:
//!   `${ISO_TIMESTAMP}  ${LEVEL} ${MODULE}: ${MESSAGE}`
//!
//! Single-threaded, returns a String. Format-compatible with the TS
//! version so logs from the old and new projects line up in any
//! aggregator.

use chrono::Utc;

/// Right-padded level field – `level.padStart(5)` in the TS version.
/// `INFO` → `" INFO"`, `ERROR` → `"ERROR"`, etc.
pub fn format_log(level: &str, module: &str, message: &str) -> String {
    let padded = if level.len() >= 5 {
        level.to_owned()
    } else {
        format!("{level:>5}")
    };
    format!("{} {} {}: {}", iso_timestamp(), padded, module, message)
}

/// RFC-3339 UTC timestamp with 6 fractional digits (fake-microsecond
/// precision via `000` pad, matches the TS version byte-for-byte).
pub fn iso_timestamp() -> String {
    let now = Utc::now();
    let mut s = now.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
    // Pad the 3-digit millis to 6 digits as the TS does.
    if let Some(dot) = s.find('.') {
        let mut prefix = s[..=dot].to_owned();
        let suffix = &s[dot + 1..];
        // suffix is "NNNZ" – strip Z, pad, restore
        let digits: String = suffix.chars().take_while(|c| c.is_ascii_digit()).collect();
        let padded = format!("{:0<6}", digits);
        prefix.push_str(&padded);
        prefix.push('Z');
        s = prefix;
    }
    s
}

pub fn info(module: &str, msg: &str) {
    eprintln!("{}", format_log("INFO", module, msg));
}

pub fn warn(module: &str, msg: &str) {
    eprintln!("{}", format_log("WARN", module, msg));
}

pub fn error(module: &str, msg: &str) {
    eprintln!("{}", format_log("ERROR", module, msg));
}

/// Helper used by `miniblox::attempt_create_account` – assembles the
/// `"{nonce} ({username})"` prefix for log lines without re-parsing.
pub fn module_line(prefix: &str, nonce: &str, username: &str) -> String {
    format!("[{prefix}] {nonce} ({username})")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn level_is_left_padded_to_five() {
        assert!(format_log("INFO", "mod", "x").contains(" INFO mod: x"));
        assert!(format_log("ERROR", "mod", "x").contains("ERROR mod: x"));
    }

    #[test]
    fn timestamp_has_iso_shape() {
        let t = iso_timestamp();
        assert_eq!(t.len(), 27, "expected 27 chars (incl. 6 fractional), got {t:?}");
        assert!(t.ends_with('Z'));
        assert!(t.chars().nth(10).unwrap() == 'T');
    }
}
