use phf::phf_map;

use std::collections::HashMap;

const IGNORED: &'static [u8] = b"\n ()@&%";

const FREQUENCY_MAP: phf::Map<char, f64> = phf_map! {
    'a' => 8.167,
    'b' => 1.492,
    'c' => 2.202,
    'd' => 4.253,
    'e' => 12.702,
    'f' => 2.228,
    'g' => 2.015,
    'h' => 6.094,
    'i' => 6.966,
    'j' => 0.153,
    'k' => 1.292,
    'l' => 4.025,
    'm' => 2.406,
    'n' => 6.749,
    'o' => 7.507,
    'p' => 1.929,
    'q' => 0.095,
    'r' => 5.987,
    's' => 6.327,
    't' => 9.356,
    'u' => 2.758,
    'v' => 0.978,
    'w' => 2.560,
    'x' => 0.150,
    'y' => 1.994,
    'z' => 0.077,
    '.' => 0.653,
    ',' => 0.613,
    '"' => 0.267,
    '\''=> 0.243,
    '–' => 0.153,
    '-' => 0.153,
    '?' => 0.056,
    ':' => 0.034,
    '!' => 0.033,
    ';' => 0.032,
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
