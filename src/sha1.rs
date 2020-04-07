use std::num::Wrapping;

const H0: Wrapping<u32> = Wrapping(0x67452301);
const H1: Wrapping<u32> = Wrapping(0xEFCDAB89);
const H2: Wrapping<u32> = Wrapping(0x98BADCFE);
const H3: Wrapping<u32> = Wrapping(0x10325476);
const H4: Wrapping<u32> = Wrapping(0xC3D2E1F0);

pub fn sha1(message: &[u8]) -> Vec<u8> {
    let (mut h0, mut h1, mut h2, mut h3, mut h4) = (H0, H1, H2, H3, H4);

    let message = preprocess(message);

    let mut w = Vec::with_capacity(80);

    for chunk in message.chunks(512 / 8) {
        w.clear();
        w.resize(80, Wrapping(0));

        for i in (0..chunk.len()).step_by(4) {
            let number = u32::from_be_bytes([chunk[i], chunk[i + 1], chunk[i + 2], chunk[i + 3]]);
            w[i] = Wrapping(number);
        }

        for i in 16..80 {
            let result = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
            w[i] = Wrapping(result.0.rotate_left(1));
        }

        let (mut a, mut b, mut c, mut d, mut e) = (h0, h1, h2, h3, h4);

        for i in 0..80 {
            let f;
            let k;

            match i {
                0..=19 => {
                    f = (b & c) | ((!b) & d);
                    k = Wrapping(0x5A827999);
                }

                20..=39 => {
                    f = b ^ c ^ d;
                    k = Wrapping(0x6ED9EBA1);
                }

                40..=59 => {
                    f = (b & c) | (b & d) | (c & d);
                    k = Wrapping(0x8F1BBCDC);
                }

                _ => {
                    f = b ^ c ^ d;
                    k = Wrapping(0xCA62C1D6);
                }
            }

            let temp = Wrapping(a.0.rotate_left(5)) + f + e + k + w[i];
            e = d;
            d = c;
            c = Wrapping(b.0.rotate_left(30));
            b = a;
            a = temp;
        }

        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
    }

    let mut result = Vec::with_capacity(20);
    result.extend_from_slice(&h0.0.to_be_bytes());
    result.extend_from_slice(&h1.0.to_be_bytes());
    result.extend_from_slice(&h2.0.to_be_bytes());
    result.extend_from_slice(&h3.0.to_be_bytes());
    result.extend_from_slice(&h4.0.to_be_bytes());

    result
}

fn preprocess(message: &[u8]) -> Vec<u8> {
    let current_mod = (message.len() * 8 + 1) % 512;
    let zeroes_to_append = if current_mod < 448 {
        448 - current_mod
    } else {
        (512 - current_mod) + 448
    };

    let bytes_to_append = (zeroes_to_append + 1) / 8;
    let mut result = Vec::with_capacity(message.len() + bytes_to_append + 4);
    result.extend_from_slice(message);

    let first_byte = 1 << 7;
    result.push(first_byte);

    for _ in 1..bytes_to_append {
        result.push(0);
    }

    // add 64-bit length
    let length_in_bits = (message.len() * 8) as u64;
    result.extend_from_slice(&length_in_bits.to_be_bytes());

    result
}

#[cfg(test)]
use crate::encoding::bytes_to_hex;

#[test]
fn test_preprocess() {
    let result = preprocess(b"abc");

    assert_eq!((result.len() * 8) % 512, 0);
    assert_eq!(result[3], 1 << 7);
    assert_eq!(result[result.len() - 1], 24);
}

#[test]
fn test_empty_string() {
    let result = sha1(&[]);
    let hex_result = bytes_to_hex(&result);

    assert_eq!(hex_result, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
}

#[test]
fn test_sha1_quick_brown_fox() {
    let result = sha1(b"The quick brown fox jumps over the lazy dog");
    let hex_result = bytes_to_hex(&result);

    assert_eq!(hex_result, "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12");
}

#[test]
fn test_sha1_large_data() {
    use std::fs;

    let test_data = fs::read("./data/01-08.txt").unwrap();
    let result = sha1(&test_data);
    let hex_result = bytes_to_hex(&result);

    assert_eq!(hex_result, "1189d970a62f1b5c96db6965c388cde381f82471");
}
