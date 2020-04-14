use rug::{Assign, Integer};

use cryptopals::{dh, encoding::bytes_to_hex, utils::check_mark};

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

    let (public_key_a, private_key_a) = dh::generate_keypair(&base, &modulus);
    let (public_key_b, private_key_b) = dh::generate_keypair(&base, &modulus);

    let session_key_a = dh::derive_session_key(&public_key_b, &private_key_a, &modulus);
    println!(
        "Generated session key using priv A + pub B: {}",
        bytes_to_hex(&session_key_a.to_aes_key())
    );

    let session_key_b = dh::derive_session_key(&public_key_a, &private_key_b, &modulus);
    println!(
        "Generated session key using priv B + pub A: {}",
        bytes_to_hex(&session_key_b.to_aes_key())
    );

    println!(
        "Keys match {}",
        check_mark(session_key_a.to_aes_key() == session_key_b.to_aes_key())
    );
}
