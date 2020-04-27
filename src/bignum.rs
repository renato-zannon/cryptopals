use rand::prelude::*;
use rug::integer::Order;
use rug::{
    ops::{DivFrom, PowAssign},
    Assign, Integer,
};
use std::convert::TryInto;

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

pub fn random_prime(bits: u32) -> Integer {
    use openssl::bn::BigNum;

    let mut openssl_num = BigNum::new().unwrap();
    openssl_num
        .generate_prime(bits.try_into().expect("i32 overflow"), false, None, None)
        .unwrap();
    let bytes = openssl_num.to_vec();

    let mut prime = Integer::with_capacity(bytes.len() * 8);
    prime.assign_digits(&bytes, Order::Msf);
    prime
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

pub fn to_bytes(integer: &Integer) -> Vec<u8> {
    integer.to_digits(Order::Msf)
}

pub fn invmod(x: &Integer, m: &Integer) -> Integer {
    let result = egcd(x, m);
    if result.gcd != 1 {
        panic!("Numbers aren't coprime");
    }

    let mut result = result.s_coefficient;

    if result < 0 {
        result += m;
    }

    result
}

pub fn lcm(a: &Integer, b: &Integer) -> Integer {
    let mut result = gcd(a, b);

    result.div_from(a);
    result *= b;

    result
}

#[derive(Debug)]
pub struct EGCDResult {
    pub gcd: Integer,
    pub s_coefficient: Integer,
    pub t_coefficient: Integer,
}

pub fn egcd(a: &Integer, b: &Integer) -> EGCDResult {
    let mut prev_r = Integer::from(a);
    let mut r = Integer::from(b);

    let mut s = Integer::from(0);
    let mut prev_s = Integer::from(1);

    let mut t = Integer::from(1);
    let mut prev_t = Integer::from(0);

    if r > prev_r {
        std::mem::swap(&mut r, &mut prev_r);
        std::mem::swap(&mut s, &mut t);
        std::mem::swap(&mut prev_s, &mut prev_t);
    }

    let mut q = Integer::new();

    while r > 0 {
        q.assign(&prev_r / &r);

        prev_r -= (&q) * (&r);
        std::mem::swap(&mut prev_r, &mut r);

        prev_t -= (&q) * (&t);
        std::mem::swap(&mut prev_t, &mut t);

        prev_s -= (&q) * (&s);
        std::mem::swap(&mut prev_s, &mut s);
    }

    EGCDResult {
        gcd: prev_r,
        s_coefficient: prev_s,
        t_coefficient: prev_t,
    }
}

pub fn gcd(a: &Integer, b: &Integer) -> Integer {
    let mut prev_r = Integer::from(a);
    let mut r = Integer::from(b);
    if r > prev_r {
        std::mem::swap(&mut r, &mut prev_r);
    }

    while r > 0 {
        prev_r %= &r;
        std::mem::swap(&mut prev_r, &mut r);
    }

    prev_r
}
