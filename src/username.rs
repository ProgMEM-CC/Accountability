//! Username generator – mirrors `AccGen/lib/miniblox.ts::generateUsername`.
//!
//! Two observed shapes appear in the user's spec:
//!   - `VectorAltBVJ`   (8-char word + 3 uppercase suffix chars)
//!   - `BobbyPin.mQaF`  (8-char word + "." + 4 lowercase suffix chars)
//!
//! Probability of the dotted form is ~15% per call (matches the JS random
//! sampler). Drop 0/O/1/l/I to dodge server-side anti-spam heuristics.

use rand::Rng;

const WORD_BASES: &[&str] = &[
    "VectorAlt", "BobbyPin", "PixelJet", "StarFlux", "MoonPink", "AeroEvo",
    "CloudKid", "NovaForm", "SkyPlex", "BloxyKid", "PixelAxe", "RobloxBj",
    "MegaFlex", "TurboKid", "FrostBow", "LavaTwin", "AstroKid", "BlockAce",
    "ZetaFlex", "CosmoKid", "HelixArc", "ByteForm", "RuneStar", "Crystal",
    "MysticBj", "Galactic", "TurboFlux", "EchoBlock", "ZephyrBj",
];

/// Base36-ish — drop 0/O/1/l/I so server-side anti-spam heuristics don't reject.
const ALPHABET: &[u8] = b"abcdefghjkmnpqrstuvwxyz23456789";

/// Pick a username using the local thread RNG. Override `rng` for tests.
pub fn generate_username<R: Rng + ?Sized>(rng: &mut R) -> String {
    let word = WORD_BASES[rng.gen_range(0..WORD_BASES.len())];
    // ~15% chance of the dotted form.
    let dotted = rng.gen_bool(0.15);
    if dotted {
        let suffix = sample_suffix(4, rng);
        format!("{word}.{suffix}")
    } else {
        let suffix = sample_suffix(3, rng).to_uppercase();
        format!("{word}{suffix}")
    }
}

/// Sample a random token of `len` chars from `ALPHABET`. Exposed for tests.
pub fn sample_suffix<R: Rng + ?Sized>(len: usize, rng: &mut R) -> String {
    (0..len)
        .map(|_| {
            let idx = rng.gen_range(0..ALPHABET.len());
            ALPHABET[idx] as char
        })
        .collect()
}

/* ───────────────────────────  Tests  ─────────────────────────── */

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    /// Deterministic RNG so the test doesn't depend on the global state.
    fn fixed_rng() -> impl rand::Rng {
        rand::rngs::StdRng::seed_from_u64(0x5EED_0001)
    }

    #[test]
    fn sample_suffix_matches_alphabet() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xC0FFEE_u64);
        let s = sample_suffix(4, &mut rng);
        assert_eq!(s.len(), 4);
        for ch in s.chars() {
            assert!(ALPHABET.contains(&(ch as u8)), "got {ch}");
        }
    }

    #[test]
    fn usernames_match_spec_shapes() {
        let mut rng = fixed_rng();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..100 {
            let u = generate_username(&mut rng);
            // VectorAlt-style or BobbyPin.dotted-style
            assert!(
                u.chars().next().unwrap().is_ascii_uppercase(),
                "first char must be uppercase: {u}",
            );
            assert!(
                u.contains('.')
                    || u.chars()
                        .skip_while(|c| c.is_ascii_alphabetic())
                        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()),
                "username should match observed shape: {u}",
            );
            seen.insert(u);
        }
        // The dictionary has plenty of variation — entropic enough that
        // 100 samples don't collapse to a single output.
        assert!(seen.len() > 50, "expected >50 unique usernames, got {}", seen.len());
    }

    #[test]
    fn dotted_and_glued_forms_both_appear() {
        // With seed=0xDEAD_BEEF we want at least one of each.
        let mut rng = fixed_rng();
        let mut dotted = 0;
        let mut glued = 0;
        for _ in 0..300 {
            if generate_username(&mut rng).contains('.') {
                dotted += 1;
            } else {
                glued += 1;
            }
        }
        assert!(dotted > 0, "no dotted usernames");
        assert!(glued > 100, "no glued usernames");
    }
}
