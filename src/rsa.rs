use rug::Integer;

use crate::bignum::{self, invmod, lcm};

#[derive(Debug)]
pub struct PublicKey {
    modulus: Integer,
    exponent: Integer,
}

#[derive(Debug)]
pub struct PrivateKey {
    modulus: Integer,
    exponent: Integer,
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
