use rand::prelude::*;
use rug::integer::Order;
use rug::{ops::PowAssign, Assign, Integer};

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
    let byte_count = modulus.significant_digits::<u8>();

    let mut result = Integer::with_capacity(bit_count);
    let mut digits: Vec<u8> = vec![0; byte_count];

    loop {
        rng.fill(&mut digits[..]);

        result.assign_digits(&digits, Order::Msf);

        if &result < modulus {
            break;
        }
    }

    result
}

pub fn from_hex(hex: &str) -> Integer {
    let mut integer = Integer::new();
    integer.assign(Integer::parse_radix(hex, 16).unwrap());
    integer
}

pub fn from_bytes(bytes: &[u8]) -> Integer {
    let mut integer = Integer::with_capacity(bytes.len() * 8);
    integer.assign_digits(bytes, Order::Msf);
    integer
}
