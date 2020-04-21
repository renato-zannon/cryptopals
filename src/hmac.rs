use std::cmp::Ordering;

use crate::{sha1, sha256, xor};

pub trait HashFunction {
    const BLOCK_SIZE: usize;

    fn compute(message: &[u8]) -> Vec<u8>;
}

impl HashFunction for sha1::SHA1 {
    const BLOCK_SIZE: usize = 64;

    fn compute(message: &[u8]) -> Vec<u8> {
        sha1::sha1(message)
    }
}

impl HashFunction for sha256::SHA256 {
    const BLOCK_SIZE: usize = 64;

    fn compute(message: &[u8]) -> Vec<u8> {
        sha256::sha256(message)
    }
}

pub fn hmac_sha1(key: &[u8], message: &[u8]) -> Vec<u8> {
    hmac::<sha1::SHA1>(key, message)
}

pub fn hmac_sha256(key: &[u8], message: &[u8]) -> Vec<u8> {
    hmac::<sha256::SHA256>(key, message)
}

pub fn hmac<H: HashFunction>(key: &[u8], message: &[u8]) -> Vec<u8> {
    let derived_key = match key.len().cmp(&H::BLOCK_SIZE) {
        Ordering::Greater => H::compute(key),
        Ordering::Equal => key.to_vec(),

        Ordering::Less => {
            let mut padded = key.to_vec();
            padded.resize(H::BLOCK_SIZE, 0_u8);
            padded
        }
    };

    let mut o_key_pad = xor::rotating_xor(&derived_key, &[0x5c]);
    let mut i_key_pad = xor::rotating_xor(&derived_key, &[0x36]);

    i_key_pad.extend_from_slice(message);
    let inner_hash = H::compute(&i_key_pad);

    o_key_pad.extend_from_slice(&inner_hash);

    H::compute(&o_key_pad)
}

#[cfg(test)]
use crate::encoding::bytes_to_hex;

#[test]
fn test_hmac_sha1() {
    let result = hmac_sha1(b"key", b"The quick brown fox jumps over the lazy dog");
    let hex_result = bytes_to_hex(&result);

    assert_eq!(hex_result, "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9");
}
