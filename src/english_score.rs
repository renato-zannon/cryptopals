use phf::phf_map;

use std::collections::HashMap;

const IGNORED: &'static [u8] = b"\n ()@&%";

const FREQUENCY_MAP: phf::Map<char, f64> = phf_map! {
    'a' => 7.952,
    'b' => 1.453,
    'c' => 2.144,
    'd' => 4.141,
    'e' => 12.368,
    'f' => 2.169,
    'g' => 1.962,
    'h' => 5.934,
    'i' => 6.783,
    'j' => 0.149,
    'k' => 1.258,
    'l' => 3.919,
    'm' => 2.343,
    'n' => 6.572,
    'o' => 7.31,
    'p' => 1.878,
    'q' => 0.093,
    'r' => 5.83,
    's' => 6.161,
    't' => 9.11,
    'u' => 2.686,
    'v' => 0.952,
    'w' => 2.493,
    'x' => 0.146,
    'y' => 1.942,
    'z' => 0.075,
    '.' => 0.636,
    ',' => 0.597,
    '"' => 0.26,
    '\''=> 0.237,
    '–' => 0.149,
    '-' => 0.149,
    '?' => 0.055,
    ':' => 0.033,
    '!' => 0.032,
    ';' => 0.031
};

pub fn english_score(plaintext: &[u8]) -> f64 {
    if plaintext.len() == 0 {
        return 0.0;
    }

    let mut unexpected_count = 0;
    let mut uppercase_count = 0;

    let mut counts: HashMap<char, u32> = FREQUENCY_MAP.keys().map(|&k| (k, 0)).collect();

    for &original_byte in plaintext {
        let mut byte = original_byte;

        if byte >= 'A' as u8 && byte <= 'Z' as u8 {
            byte += 32;
            uppercase_count += 1;
        }

        if !FREQUENCY_MAP.contains_key(&(byte as char)) {
            if !IGNORED.contains(&byte) {
                unexpected_count += 1;
            }

            continue;
        }

        counts
            .entry(byte as char)
            .and_modify(|count| *count += 1)
            .or_insert(1);
    }

    let mut score = 100f64;
    let plaintext_len = plaintext.len() as f64;

    for (chr, &count) in counts.iter() {
        let expected = FREQUENCY_MAP[chr];
        let frequency = (100.0 * count as f64) / plaintext_len;

        let diff = (expected - frequency).abs();
        score -= diff;
    }

    score -= (unexpected_count * 2) as f64;
    score -= uppercase_count as f64;

    score
}

use super::xor::xor_with_byte;

pub fn single_byte_key_with_best_score(ciphertext: &[u8]) -> u8 {
    let mut best_score = std::f64::MIN;
    let mut best_key = 0;

    for possible_key in 0x00..=0xff {
        let plaintext = xor_with_byte(&ciphertext, possible_key);
        let score = english_score(&plaintext);

        if score > best_score {
            best_score = score;
            best_key = possible_key;
        }
    }

    best_key
}
