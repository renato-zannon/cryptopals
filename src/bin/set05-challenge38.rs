use rand::prelude::*;
use rayon::prelude::*;
use rug::{integer::Order, Integer};

use std::fs::File;
use std::io::{prelude::*, BufReader, SeekFrom};

use cryptopals::{bignum, hmac::hmac_sha256, sha256::sha256};

fn main() {
    // By setting b = 1 (therefore B=g), u=1 we get:
    // S = g^(a + x) mod n = (g^a mod n)(g^x) mod n = A(g^x) mod n
    let u = Integer::from(1);
    let public_key = Integer::from(&*simple_srp::BASE);

    // Empty salt makes things a little bit easier
    let salt = &[];

    let (client_public_key, client_hmac) = get_client_hmac(salt, &public_key, &u);

    // Simulating password-cracking by brute-forcing using a wordlist.
    // Got an excuse to use rayon here at least :)
    let words_file = BufReader::new(File::open("/usr/share/dict/words").unwrap());
    let mut all_words: Vec<_> = words_file.lines().map(|word| word.unwrap()).collect();
    all_words.shuffle(&mut thread_rng());

    let word = all_words
        .par_iter()
        .find_any(|word| {
            let hmac = hmac_for_guess(&client_public_key, word.as_bytes());
            hmac == client_hmac
        })
        .unwrap();

    println!("Cracked password: {}", word);
}

fn hmac_for_guess(client_public_key: &Integer, guess: &[u8]) -> Vec<u8> {
    let x_h = sha256(guess);
    let x = bignum::from_bytes(&x_h);

    let mut s = bignum::modexp(&simple_srp::BASE, &x, &simple_srp::NIST_PRIME);
    s *= client_public_key;
    s %= &*simple_srp::NIST_PRIME;

    let session_key = sha256(&s.to_digits(Order::LsfLe));
    hmac_sha256(&session_key, &[])
}

fn get_client_hmac(salt: &[u8], server_public_key: &Integer, u: &Integer) -> (Integer, Vec<u8>) {
    let password = random_word();
    let client = simple_srp::Client::new(password);
    let hmac = client.compute_session_hmac(salt, server_public_key, u);

    (client.public_key().clone(), hmac)
}

fn random_word() -> Vec<u8> {
    let mut rng = thread_rng();

    let mut words_file = File::open("/usr/share/dict/words").unwrap();

    let word_file_size = words_file.metadata().unwrap().len();
    let initial_index = rng.gen_range(0, word_file_size - 100);

    words_file.seek(SeekFrom::Start(initial_index)).unwrap();

    let next_line = BufReader::with_capacity(32, words_file)
        .lines()
        .skip(1)
        .next();

    match next_line {
        Some(Ok(password)) => {
            println!("Randomly-selected password: {}", password);
            password.into_bytes()
        }
        _ => panic!(),
    }
}

mod simple_srp {
    use lazy_static::lazy_static;
    use rand::prelude::*;
    use rug::integer::Order;
    use rug::Integer;

    use cryptopals::{
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
        pub static ref BASE: Integer = Integer::from(2);
        static ref MAX_U: Integer = {
            let digits = [0xff_u8; 128 / 8];
            Integer::from_digits(&digits, Order::Msf)
        };
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
                public_key: public_key,
                private_key,
                password,
            }
        }

        pub fn public_key(&self) -> &Integer {
            &self.public_key
        }

        pub fn compute_session_hmac(
            &self,
            salt: &[u8],
            server_pub: &Integer,
            u: &Integer,
        ) -> Vec<u8> {
            let session_key = self.compute_session_key(salt, &server_pub, u);
            hmac_sha256(&session_key, salt)
        }

        fn compute_session_key(&self, salt: &[u8], server_pub: &Integer, u: &Integer) -> Vec<u8> {
            let x_h = sha256_concat(&[salt, &self.password]);
            let x = bignum::from_bytes(&x_h);

            let s = self.compute_s(server_pub, &x, &u);
            sha256(&s.to_digits(Order::LsfLe))
        }

        fn compute_s(&self, server_pub: &Integer, x: &Integer, u: &Integer) -> Integer {
            let mut base = Integer::from(server_pub);

            // exp = (a + u * x)
            let mut exp = Integer::from(u);
            exp *= x;
            exp += &self.private_key;

            // base = base ** exp % N
            base.pow_mod_mut(&exp, &NIST_PRIME).unwrap();

            base
        }
    }

    fn sha256_concat(slices: &[&[u8]]) -> Vec<u8> {
        let mut sha256 = SHA256::new();
        for &slice in slices {
            sha256.update(slice);
        }

        sha256.finalize()
    }
}
