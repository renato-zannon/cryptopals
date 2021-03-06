use rand::prelude::*;
use rug::integer::Order;
use rug::Integer;

use crate::{bignum, sha1};

#[derive(Debug, Clone)]
pub struct PublicKey(pub Integer);

#[derive(Debug)]
pub struct PrivateKey(pub Integer);

#[derive(PartialEq, Eq, Debug)]
pub struct SessionKey(pub Integer);

const DEFAULT_MODULUS: &str = "\
  ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024\
  e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd\
  3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec\
  6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f\
  24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361\
  c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552\
  bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff\
  fffffffffffff\
";

const DEFAULT_BASE: u32 = 2;

#[derive(Clone, Debug)]
pub struct Parameters {
    pub modulus: Integer,
    pub base: Integer,
}

impl Parameters {
    pub fn default() -> Self {
        let modulus = bignum::from_hex(DEFAULT_MODULUS);
        let base = Integer::from(DEFAULT_BASE);

        Self { modulus, base }
    }

    pub fn new(modulus: Integer, base: Integer) -> Self {
        Self { modulus, base }
    }

    pub fn generate_keypair(&self) -> (PublicKey, PrivateKey) {
        generate_keypair(&self.base, &self.modulus)
    }

    pub fn derive_session_key(
        &self,
        public_key: &PublicKey,
        private_key: &PrivateKey,
    ) -> SessionKey {
        derive_session_key(public_key, private_key, &self.modulus)
    }
}

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
    let private_key = bignum::random_integer(&modulus, &mut thread_rng());
    let public_key = bignum::modexp(&base, &private_key, &modulus);

    (PublicKey(public_key), PrivateKey(private_key))
}

pub fn derive_session_key(
    public_key: &PublicKey,
    private_key: &PrivateKey,
    modulus: &Integer,
) -> SessionKey {
    let key = bignum::modexp(&public_key.0, &private_key.0, modulus);
    SessionKey(key)
}
