use lazy_static::lazy_static;
use rand::prelude::*;
use rug::integer::Order;
use rug::{ops::SubFrom, Integer};

use crate::{
    bignum,
    hmac::hmac_sha256,
    sha256::{sha256, SHA256},
};

const NIST_PRIME_STR: &str = "\
  ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024\
  e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd\
  3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec\
  6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f\
  24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361\
  c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552\
  bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff\
  fffffffffffff\
";

lazy_static! {
    pub static ref NIST_PRIME: Integer = bignum::from_hex(NIST_PRIME_STR);
    static ref BASE: Integer = Integer::from(2);
    static ref K_PARAM: Integer = Integer::from(3);
}

pub struct Verifier {
    salt: Vec<u8>,
    v: Integer,
}

impl Verifier {
    pub fn new(password: &[u8]) -> Self {
        let salt = random_salt(&mut thread_rng());
        let x_h = sha256_concat(&[&salt, password]);
        let x = bignum::from_bytes(&x_h);
        let v = bignum::modexp(&BASE, &x, &NIST_PRIME);

        Self { v, salt }
    }
}

pub struct Server {
    verifier: Verifier,
    private_key: Integer,
    public_key: Integer,
}

impl Server {
    pub fn new(verifier: Verifier) -> Self {
        let private_key = bignum::random_integer(&NIST_PRIME, &mut thread_rng());

        let mut public_key = bignum::modexp(&BASE, &private_key, &NIST_PRIME);
        public_key += (&verifier.v) * (&*K_PARAM);
        public_key %= &*NIST_PRIME;

        Self {
            verifier,
            public_key,
            private_key,
        }
    }

    pub fn verify_session_hmac(&self, client_pub: &Integer, client_hmac: &[u8]) -> bool {
        let session_key = self.compute_session_key(&client_pub);
        let computed_hmac = hmac_sha256(&session_key, &self.verifier.salt);

        client_hmac == computed_hmac.as_slice()
    }

    fn compute_session_key(&self, client_pub: &Integer) -> Vec<u8> {
        // base = (A * v ** u)
        let mut base = Integer::from(&self.verifier.v);
        let u = compute_u(client_pub, &self.public_key);
        base.pow_mod_mut(&u, &NIST_PRIME).unwrap();
        base *= client_pub;

        // base = base ** b % N
        base.pow_mod_mut(&self.private_key, &NIST_PRIME).unwrap();

        // K = SHA256(S)
        sha256(&base.to_digits(Order::LsfLe))
    }

    pub fn public_key(&self) -> &Integer {
        &self.public_key
    }

    pub fn salt(&self) -> &[u8] {
        self.verifier.salt.as_slice()
    }
}

pub struct Client {
    public_key: Integer,
    private_key: Integer,
    password: Vec<u8>,
}

impl Client {
    pub fn new(password: Vec<u8>) -> Self {
        let private_key = bignum::random_integer(&NIST_PRIME, &mut thread_rng());
        let public_key = bignum::modexp(&BASE, &private_key, &NIST_PRIME);

        Self {
            public_key,
            private_key,
            password,
        }
    }

    pub fn public_key(&self) -> &Integer {
        &self.public_key
    }

    pub fn compute_session_hmac(&self, salt: &[u8], server_pub: &Integer) -> Vec<u8> {
        let session_key = self.compute_session_key(salt, &server_pub);
        hmac_sha256(&session_key, salt)
    }

    fn compute_session_key(&self, salt: &[u8], server_pub: &Integer) -> Vec<u8> {
        let x_h = sha256_concat(&[salt, &self.password]);
        let x = bignum::from_bytes(&x_h);

        let s = self.compute_s(&server_pub, &x);
        sha256(&s.to_digits(Order::LsfLe))
    }

    fn compute_s(&self, server_pub: &Integer, x: &Integer) -> Integer {
        // base = (B - k * g**x)
        let mut base = Integer::from(&*BASE);
        base.pow_mod_mut(&x, &NIST_PRIME).unwrap();
        base *= &*K_PARAM;
        base.sub_from(server_pub);

        // exp = (a + u * x)
        let mut exp = compute_u(&self.public_key, server_pub);
        exp *= x;
        exp += &self.private_key;

        // base = base ** exp % N
        base.pow_mod_mut(&exp, &NIST_PRIME).unwrap();

        base
    }
}

fn compute_u(client_pub: &Integer, server_pub: &Integer) -> Integer {
    let u_h = sha256_concat(&[
        &client_pub.to_digits(Order::LsfLe),
        &server_pub.to_digits(Order::LsfLe),
    ]);

    bignum::from_bytes(&u_h)
}

fn random_salt<R: Rng>(rng: &mut R) -> Vec<u8> {
    let mut salt = vec![0; 16];
    rng.fill(&mut salt[..]);

    salt
}

fn sha256_concat(slices: &[&[u8]]) -> Vec<u8> {
    let mut sha256 = SHA256::new();
    for &slice in slices {
        sha256.update(slice);
    }

    sha256.finalize()
}
