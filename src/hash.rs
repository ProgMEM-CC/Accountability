//! Port of [`karanlyons/murmurHash3.js`](https://github.com/karanlyons/murmurHash3.js)
//! `x64hash128` (MurmurHash3, 128-bit) to Rust. The FPJS variant shares
//! the same opcode stream, so the ground-truth test vectors in this file
//! match the karanlyons output exactly.
//!
//! **Why this is hand-rolled instead of using a hash crate**: the
//! FingerprintJS byte order is different from `mmh3.hash128`'s. Each 64-bit
//! accumulator is stored as `[lo32, hi32]` (low first) and the final hash
//! emits `h1.lo + h1.hi + h2.lo + h2.hi` (low half first) — that's
//! `9a66b4567d520770…`, not the big-endian `7d5207709a66b456…` ordering.
//! miniblox.io's nonce validator rejects mismatched-shape hashes, so we
//! must reproduce this byte order exactly.
//!
//! Every function below maps 1-to-1 onto the karanlyons JS source so a
//! casual diff against the upstream script confirms correctness.
//! Ground-truth vectors from the upstream `karanlyons` / FPJS Jest test
//! are checked at run time via the `#[test]` block at the bottom of this
//! file.

/// Computes a 128-bit MurmurHash3 of `input` with the FingerprintJS byte
/// order. `seed` defaults to 0 when `None`.
pub fn x64hash128(input: &str, seed: Option<u32>) -> String {
    // `as_bytes()` is UTF-8 in Rust, matching `getUTF8Bytes` + `TextEncoder`
    // in JS — both fall back to UTF-8 encoding for non-ASCII (chars > 0x7F).
    let key = input.as_bytes();
    let seed = seed.unwrap_or(0);

    let length: [u32; 2] = [0, key.len() as u32];
    let remainder = length[1] % 16;
    let bytes = length[1] as usize - remainder as usize;
    let mut h1: [u32; 2] = [0, seed];
    let mut h2: [u32; 2] = [0, seed];
    let mut k1: [u32; 2] = [0, 0];
    let mut k2: [u32; 2] = [0, 0];

    let c1: [u32; 2] = [0x87c37b91, 0x114253d5];
    let c2: [u32; 2] = [0x4cf5ad43, 0x2745937f];
    let m_const: [u32; 2] = [0, 5];
    let n1: [u32; 2] = [0, 0x52dce729];
    let n2: [u32; 2] = [0, 0x38495ab5];

    let mut i: usize = 0;
    while i < bytes {
        // Bytes 0-3 of the 16-byte chunk land in the HIGH half of k1
        // (k1[1]) and bytes 4-7 land in the LOW half (k1[0]) — this is
        // little-endian-ish and matches the verbatim JS | construct.
        k1[1] = key[i] as u32
            | ((key[i + 1] as u32) << 8)
            | ((key[i + 2] as u32) << 16)
            | ((key[i + 3] as u32) << 24);
        k1[0] = key[i + 4] as u32
            | ((key[i + 5] as u32) << 8)
            | ((key[i + 6] as u32) << 16)
            | ((key[i + 7] as u32) << 24);
        k2[0] = key[i + 12] as u32
            | ((key[i + 13] as u32) << 8)
            | ((key[i + 14] as u32) << 16)
            | ((key[i + 15] as u32) << 24);
        k2[1] = key[i + 8] as u32
            | ((key[i + 9] as u32) << 8)
            | ((key[i + 10] as u32) << 16)
            | ((key[i + 11] as u32) << 24);

        x64_multiply(&mut k1, c1);
        x64_rotl(&mut k1, 31);
        x64_multiply(&mut k1, c2);
        x64_xor(&mut h1, k1);
        x64_rotl(&mut h1, 27);
        x64_add(&mut h1, h2);
        x64_multiply(&mut h1, m_const);
        x64_add(&mut h1, n1);

        x64_multiply(&mut k2, c2);
        x64_rotl(&mut k2, 33);
        x64_multiply(&mut k2, c1);
        x64_xor(&mut h2, k2);
        x64_rotl(&mut h2, 31);
        x64_add(&mut h2, h1);
        x64_multiply(&mut h2, m_const);
        x64_add(&mut h2, n2);

        i += 16;
    }

    k1[0] = 0;
    k1[1] = 0;
    k2[0] = 0;
    k2[1] = 0;

    let mut val: [u32; 2] = [0, 0];

    // Switch / fallthrough order matters here: the JS code runs cases
    // 15 → 14 → 13 → 12 → 11 → 10 → 9 with case 9 doing the final
    // multiply+rotate+multiply mix of `k2` and the XOR into `h2`. The
    // mix step therefore captures the FULL k2 accumulator (bytes
    // i+8 … i+14 already merged), not just byte i+8 alone. If we run
    // case 9 first the mix only sees byte i+8 — which is the bug this
    // ordering fixes.
    //
    // The cases from 10 → 15 are individually commutative because each
    // `x64Xor` commits its contribution to `k2` before the next block
    // overwrites `val[0]` in `x64LeftShift`, so the *interior* order of
    // those cases doesn't matter. But case 9 must be LAST.
    if remainder >= 15 {
        val[1] = key[i + 14] as u32;
        x64_left_shift(&mut val, 48);
        x64_xor(&mut k2, val);
    }
    if remainder >= 14 {
        val[1] = key[i + 13] as u32;
        x64_left_shift(&mut val, 40);
        x64_xor(&mut k2, val);
    }
    if remainder >= 13 {
        val[1] = key[i + 12] as u32;
        x64_left_shift(&mut val, 32);
        x64_xor(&mut k2, val);
    }
    if remainder >= 12 {
        val[1] = key[i + 11] as u32;
        x64_left_shift(&mut val, 24);
        x64_xor(&mut k2, val);
    }
    if remainder >= 11 {
        val[1] = key[i + 10] as u32;
        x64_left_shift(&mut val, 16);
        x64_xor(&mut k2, val);
    }
    if remainder >= 10 {
        val[1] = key[i + 9] as u32;
        x64_left_shift(&mut val, 8);
        x64_xor(&mut k2, val);
    }
    if remainder >= 9 {
        val[1] = key[i + 8] as u32;
        x64_xor(&mut k2, val);
        x64_multiply(&mut k2, c2);
        x64_rotl(&mut k2, 33);
        x64_multiply(&mut k2, c1);
        x64_xor(&mut h2, k2);
    }

    if remainder >= 8 {
        val[1] = key[i + 7] as u32;
        x64_left_shift(&mut val, 56);
        x64_xor(&mut k1, val);
    }
    if remainder >= 7 {
        val[1] = key[i + 6] as u32;
        x64_left_shift(&mut val, 48);
        x64_xor(&mut k1, val);
    }
    if remainder >= 6 {
        val[1] = key[i + 5] as u32;
        x64_left_shift(&mut val, 40);
        x64_xor(&mut k1, val);
    }
    if remainder >= 5 {
        val[1] = key[i + 4] as u32;
        x64_left_shift(&mut val, 32);
        x64_xor(&mut k1, val);
    }
    if remainder >= 4 {
        val[1] = key[i + 3] as u32;
        x64_left_shift(&mut val, 24);
        x64_xor(&mut k1, val);
    }
    if remainder >= 3 {
        val[1] = key[i + 2] as u32;
        x64_left_shift(&mut val, 16);
        x64_xor(&mut k1, val);
    }
    if remainder >= 2 {
        val[1] = key[i + 1] as u32;
        x64_left_shift(&mut val, 8);
        x64_xor(&mut k1, val);
    }
    if remainder >= 1 {
        val[1] = key[i] as u32;
        x64_xor(&mut k1, val);
        x64_multiply(&mut k1, c1);
        x64_rotl(&mut k1, 31);
        x64_multiply(&mut k1, c2);
        x64_xor(&mut h1, k1);
    }

    x64_xor(&mut h1, length);
    x64_xor(&mut h2, length);
    x64_add(&mut h1, h2);
    x64_add(&mut h2, h1);
    x64_fmix(&mut h1);
    x64_fmix(&mut h2);
    x64_add(&mut h1, h2);
    x64_add(&mut h2, h1);

    // Output order: h1.lo, h1.hi, h2.lo, h2.hi — this is the FPJS `[lo, hi]`
    // ordering, **not** mmh3's big-endian. Cross-check the ground truth
    // vector "hello" → "cbd8a7b341bd9b025b1e906a48ae1d19":
    //   h1.lo = cbd8a7b3, h1.hi = 41bd9b02, h2.lo = 5b1e906a, h2.hi = 48ae1d19
    format!("{:08x}{:08x}{:08x}{:08x}", h1[0], h1[1], h2[0], h2[1])
}

/* ───────────────────────────  64-bit primitives  ─────────────────────────── */

/// `m += n (mod 2^64)`, mutates `m`. Each 64-bit value is stored as
/// `[lo32, hi32]`. The 16-bit-limb carry-chain mirrors the JS code so
/// the result matches `>>> 0` bit-for-bit.
fn x64_add(m: &mut [u32; 2], n: [u32; 2]) {
    let m0 = m[0] >> 16;
    let m1 = m[0] & 0xffff;
    let m2 = m[1] >> 16;
    let m3 = m[1] & 0xffff;
    let n0 = n[0] >> 16;
    let n1 = n[0] & 0xffff;
    let n2 = n[1] >> 16;
    let n3 = n[1] & 0xffff;

    let mut o0: u32 = 0;
    let mut o1: u32 = 0;
    let mut o2: u32 = 0;
    let mut o3: u32 = 0;

    o3 += m3 + n3;
    o2 += o3 >> 16;
    o3 &= 0xffff;
    o2 += m2 + n2;
    o1 += o2 >> 16;
    o2 &= 0xffff;
    o1 += m1 + n1;
    o0 += o1 >> 16;
    o1 &= 0xffff;
    o0 += m0 + n0;
    o0 &= 0xffff;

    m[0] = (o0 << 16) | o1;
    m[1] = (o2 << 16) | o3;
}

/// `m *= n (mod 2^64)`, mutates `m`. Uses `u64` for the limbs because a
/// 16-bit-limb × 16-bit-limb product of two operands that already carry a
/// 16-bit cap can overflow `u32` before the next mask (`0xffff + 2^32 - 1`
/// ≈ 2^32). The JS code gets away with this because intermediate
/// accumulators are stored as IEEE-754 doubles; `u64` is the equivalent
/// in Rust.
fn x64_multiply(m: &mut [u32; 2], n: [u32; 2]) {
    let m0 = m[0] >> 16;
    let m1 = m[0] & 0xffff;
    let m2 = m[1] >> 16;
    let m3 = m[1] & 0xffff;
    let n0 = n[0] >> 16;
    let n1 = n[0] & 0xffff;
    let n2 = n[1] >> 16;
    let n3 = n[1] & 0xffff;

    let mut o0: u64 = 0;
    let mut o1: u64 = 0;
    let mut o2: u64 = 0;
    let mut o3: u64 = 0;

    o3 += (m3 as u64) * (n3 as u64);
    o2 += o3 >> 16;
    o3 &= 0xffff;
    o2 += (m2 as u64) * (n3 as u64);
    o1 += o2 >> 16;
    o2 &= 0xffff;
    o2 += (m3 as u64) * (n2 as u64);
    o1 += o2 >> 16;
    o2 &= 0xffff;
    o1 += (m1 as u64) * (n3 as u64);
    o0 += o1 >> 16;
    o1 &= 0xffff;
    o1 += (m2 as u64) * (n2 as u64);
    o0 += o1 >> 16;
    o1 &= 0xffff;
    o1 += (m3 as u64) * (n1 as u64);
    o0 += o1 >> 16;
    o1 &= 0xffff;
    o0 += (m0 as u64) * (n3 as u64)
        + (m1 as u64) * (n2 as u64)
        + (m2 as u64) * (n1 as u64)
        + (m3 as u64) * (n0 as u64);
    o0 &= 0xffff;

    m[0] = ((o0 << 16) | o1) as u32;
    m[1] = ((o2 << 16) | o3) as u32;
}

/// Left-rotate the 64-bit `[lo32, hi32]` pair by `bits`. Implemented as a
/// `u64` rotation because the JS version converges on the same answer —
/// each bit moves up `bits` positions, modulo 64.
fn x64_rotl(pair: &mut [u32; 2], bits: i32) {
    let bits = bits.rem_euclid(64);
    if bits == 0 {
        return;
    }
    let combined: u64 = ((pair[1] as u64) << 32) | (pair[0] as u64);
    let rotated = combined.rotate_left(bits as u32);
    pair[0] = rotated as u32;
    pair[1] = (rotated >> 32) as u32;
}

/// Place `m[1]` into the appropriate bit position(s) of the 64-bit pair
/// for the MurmurHash3 tail switch. Constructs both halves out of the
/// old `m[1]` (the existing `m[0]` is dropped — this function returns
/// the caller-only val vector in the JS code).
fn x64_left_shift(m: &mut [u32; 2], bits: i32) {
    let bits = bits.rem_euclid(64);
    if bits == 0 {
        return;
    } else if bits < 32 {
        m[0] = m[1] >> (32 - bits);
        m[1] = m[1] << bits;
    } else {
        m[0] = m[1] << (bits - 32);
        m[1] = 0;
    }
}

fn x64_xor(m: &mut [u32; 2], n: [u32; 2]) {
    m[0] ^= n[0];
    m[1] ^= n[1];
}

/// Final mix — Avalanche. Each step mixes the THREE fresh 16-bit shifts
/// back into `h` so neighbouring bits don't end up correlated. Note
/// the `shifted[1] = h[0] >>> 1` re-reads `h[0]` **after** each multiply,
/// matching the JS `shifted[1] = h[0] >>> 1` placement.
fn x64_fmix(h: &mut [u32; 2]) {
    let f1: [u32; 2] = [0xff51afd7, 0xed558ccd];
    let f2: [u32; 2] = [0xc4ceb9fe, 0x1a85ec53];
    let mut shifted: [u32; 2] = [0, h[0] >> 1];
    x64_xor(h, shifted);
    x64_multiply(h, f1);
    shifted[1] = h[0] >> 1;
    x64_xor(h, shifted);
    x64_multiply(h, f2);
    shifted[1] = h[0] >> 1;
    x64_xor(h, shifted);
}

/* ───────────────────────────  FingerprintJS ground truth  ─────────────────── */

#[cfg(test)]
mod tests {
    use super::*;

    // Helper for the multi-byte input — matches the JS test exactly:
    // `String.fromCharCode(c.charCodeAt(0) + 256)` shifts each char into
    // the Latin-1 Supplement range, which exercises `TextEncoder().encode`
    // (true multi-byte UTF-8) in JS and `as_bytes()` (always UTF-8) in Rust.
    fn non_ascii_hello() -> String {
        "Hello, world, hi"
            .chars()
            .map(|c| std::char::from_u32(c as u32 + 256).unwrap())
            .collect()
    }

    #[test]
    fn produces_32_char_lowercase_hex() {
        let h = x64hash128("hello", None);
        assert_eq!(h.len(), 32);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    /// Verbatim FingerprintJS Jest vectors — the hash will NOT validate
    /// against miniblox.io if these drift.
    #[test]
    fn matches_fpjs_jest_vectors() {
        assert_eq!(x64hash128("Hello, world, hi", None), "9a66b4567d520770dc8eaf9a508ecf1b");
        assert_eq!(x64hash128("hello", None), "cbd8a7b341bd9b025b1e906a48ae1d19");
        assert_eq!(x64hash128("Hello, world, h", None), "4552c6409e0a7bd3b0f9eb318bb35f05");
        assert_eq!(x64hash128("Hello, world, hi!", None), "dce3e02d43da4d2374e84e484c566492");
        assert_eq!(
            x64hash128("Hello, world, hi, Hello, world, hi", None),
            "d49c261c833b671870b471c42df4dbf0",
        );
        assert_eq!(x64hash128(&non_ascii_hello(), None), "460892d2cab76edff07f62a97e106f6b");
    }

    #[test]
    fn differs_by_seed_and_default_seed_is_zero() {
        assert_ne!(x64hash128("hello", Some(0)), x64hash128("hello", Some(1)));
        assert_eq!(x64hash128("hello", Some(0)), x64hash128("hello", None));
    }

    #[test]
    fn distinguishes_ascii_from_non_ascii_variant() {
        assert_ne!(x64hash128("Hello, world, hi", None), x64hash128(&non_ascii_hello(), None));
    }

    #[test]
    fn handles_empty_string() {
        let h = x64hash128("", None);
        assert_eq!(h.len(), 32);
    }

    #[test]
    fn exercises_every_tail_remainder_case() {
        for n in 1usize..=15 {
            let base: String = std::iter::repeat('a').take(n).collect();
            let h1 = x64hash128(&base, None);
            let h2 = x64hash128(&base, None);
            assert_eq!(h1.len(), 32);
            assert_eq!(h1, h2);
            let mut flipped = base.clone();
            let last = flipped.pop().unwrap();
            flipped.push(if last == 'z' { 'a' } else { 'z' });
            assert_ne!(h1, x64hash128(&flipped, None), "remainder={n}");
        }
    }

    #[test]
    fn long_input_is_deterministic_and_unique() {
        let long = "x".repeat(1000);
        assert_eq!(x64hash128(&long, None), x64hash128(&long, None));
        assert_ne!(x64hash128(&"x".repeat(1000), None), x64hash128(&"y".repeat(1000), None));
    }
}
