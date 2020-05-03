use rug::Integer;

use crate::bignum::{self, invmod, lcm};

#[derive(Debug)]
pub struct PublicKey {
    pub modulus: Integer,
    pub exponent: Integer,
}

#[derive(Debug)]
pub struct PrivateKey {
    pub modulus: Integer,
    pub exponent: Integer,
}

pub fn keygen(keysize: u32, public_exponent: Integer) -> (PublicKey, PrivateKey) {
    let mut p = bignum::random_prime(keysize / 2);
    let mut q = bignum::random_prime(keysize / 2);

    let et = {
        p -= 1;
        q -= 1;

        let et = lcm(&p, &q);
        p += 1;
        q += 1;

        et
    };

    let n = p * q;

    let d = invmod(&public_exponent, &et);

    let public_key = PublicKey {
        modulus: n.clone(),
        exponent: public_exponent,
    };
    let private_key = PrivateKey {
        modulus: n,
        exponent: d,
    };

    (public_key, private_key)
}

pub fn encrypt(public_key: &PublicKey, message: &[u8]) -> Vec<u8> {
    let message_num = bignum::from_bytes(message);
    let encrypted = bignum::modexp(&message_num, &public_key.exponent, &public_key.modulus);

    bignum::to_bytes(&encrypted)
}

pub fn decrypt(private_key: &PrivateKey, message: &[u8]) -> Vec<u8> {
    let message_num = bignum::from_bytes(message);
    let decrypted = bignum::modexp(&message_num, &private_key.exponent, &private_key.modulus);

    bignum::to_bytes(&decrypted)
}

pub const SHA256_ASN1_MARKER: &[u8] = &[
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

pub fn pkcs1_sign(private_key: &PrivateKey, message: &[u8]) -> Vec<u8> {
    let message_hash = crate::sha256::sha256(message);
    let mod_size = private_key.modulus.significant_digits::<u8>();

    let mut bytes_to_sign: Vec<u8> =
        vec![0xff; mod_size - SHA256_ASN1_MARKER.len() - message_hash.len()];
    bytes_to_sign[0] = 0x00;
    bytes_to_sign[1] = 0x01;

    bytes_to_sign.extend_from_slice(SHA256_ASN1_MARKER);
    bytes_to_sign.extend_from_slice(&message_hash);

    let to_sign = bignum::from_bytes(&bytes_to_sign);
    let signed = bignum::modexp(&to_sign, &private_key.exponent, &private_key.modulus);

    bignum::to_bytes(&signed)
}
