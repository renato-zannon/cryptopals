use rand::prelude::*;
use rug::{ops::PowAssign, Assign, Integer};

const MODULUS: &str = "\
  ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024\
  e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd\
  3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec\
  6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f\
  24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361\
  c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552\
  bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff\
  fffffffffffff\
";

const BASE: u32 = 2;

fn main() {
    let mut modulus = Integer::new();
    modulus.assign(Integer::parse_radix(MODULUS, 16).unwrap());

    let base = Integer::from(BASE);

    let private_key_a = random_integer(&modulus);
    let public_key_a = modexp(&base, &private_key_a, &modulus);

    let private_key_b = random_integer(&modulus);
    let public_key_b = modexp(&base, &private_key_b, &modulus);

    let session_key_a = modexp(&public_key_b, &private_key_a, &modulus);
    let session_key_b = modexp(&public_key_a, &private_key_b, &modulus);

    assert_eq!(session_key_a, session_key_b);

    println!("Generated session key: {}", session_key_a);
}

fn random_integer(modulus: &Integer) -> Integer {
    use rug::integer::Order;

    let byte_count = modulus.significant_bits() / 8;
    let mut digits: Vec<u8> = Vec::with_capacity(byte_count as usize);
    let mut result = Integer::new();

    loop {
        digits.resize(byte_count as usize, 0);
        thread_rng().fill(&mut digits[..]);

        result.assign_digits(&digits, Order::Msf);

        if &result < modulus {
            break;
        }
    }

    result
}

fn modexp(base: &Integer, exponent: &Integer, modulus: &Integer) -> Integer {
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
