use rand::prelude::*;
use rug::integer::Order;
use rug::{ops::PowAssign, Integer};

use crate::sha1;

#[derive(Debug)]
pub struct PublicKey(Integer);

#[derive(Debug)]
pub struct PrivateKey(Integer);

#[derive(PartialEq, Eq, Debug)]
pub struct SessionKey(Integer);

impl SessionKey {
    pub fn to_aes_key(&self) -> Vec<u8> {
        const AES_KEY_SIZE: usize = 16;

        let mut hash: Vec<u8> = sha1::sha1(&self.to_bytes());
        hash.truncate(AES_KEY_SIZE);
        hash
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_digits(Order::LsfLe)
    }
}

pub fn generate_keypair(base: &Integer, modulus: &Integer) -> (PublicKey, PrivateKey) {
    let private_key = random_integer(&modulus, &mut thread_rng());
    let public_key = modexp(&base, &private_key, &modulus);

    (PublicKey(public_key), PrivateKey(private_key))
}

pub fn derive_session_key(
    public_key: &PublicKey,
    private_key: &PrivateKey,
    modulus: &Integer,
) -> SessionKey {
    let key = modexp(&public_key.0, &private_key.0, modulus);
    SessionKey(key)
}

pub fn modexp(base: &Integer, exponent: &Integer, modulus: &Integer) -> Integer {
    if modulus == &1 {
        return Integer::from(0);
    }

    let mut result = Integer::from(1);
    let mut base = Integer::from(base % modulus);
    let mut exponent = Integer::from(exponent);

    while exponent > 0 {
        if exponent.is_odd() {
            result *= &base;
            result %= modulus;
        }

        exponent >>= 1;

        base.pow_assign(2);
        base %= modulus;
    }

    result
}

pub fn random_integer<R: Rng>(modulus: &Integer, rng: &mut R) -> Integer {
    let bit_count = modulus.significant_bits() as usize;

    let mut result = Integer::with_capacity(bit_count);
    let mut digits: Vec<u8> = vec![0; bit_count / 8];

    loop {
        rng.fill(&mut digits[..]);

        result.assign_digits(&digits, Order::Msf);

        if &result < modulus {
            break;
        }
    }

    result
}
