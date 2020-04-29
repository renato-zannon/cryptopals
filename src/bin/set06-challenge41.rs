use rug::Integer;

use cryptopals::{bignum, prelude::*, quote};

fn main() {
    let mut oracle = secret::new_oracle();
    let secret_message = quote::random();
    let known_ciphertext = oracle.encrypt(secret_message.as_bytes());
    // make sure "captured" ciphertext shows up on seen_messages
    oracle.decrypt(&known_ciphertext).unwrap();

    let discovered_message = discover_plaintext(&known_ciphertext, &mut oracle);

    println!(
        "Discovered message:\n{}",
        String::from_utf8_lossy(&discovered_message)
    );
    println!(
        "{} Discovered message matches original",
        check_mark(discovered_message == secret_message.as_bytes())
    );
}

fn discover_plaintext(ciphertext: &[u8], oracle: &mut secret::Oracle) -> Vec<u8> {
    let modulus = Integer::from(&oracle.public_key().modulus);
    let s = bignum::random_integer(&modulus, &mut rand::thread_rng());

    let ciphertext_num = bignum::from_bytes(ciphertext);

    let mut modified_ciphertext = Integer::from(
        s.pow_mod_ref(&oracle.public_key().exponent, &modulus)
            .unwrap(),
    );
    modified_ciphertext *= &ciphertext_num;
    modified_ciphertext %= &modulus;

    let modified_plaintext = oracle
        .decrypt(&bignum::to_bytes(&modified_ciphertext))
        .expect("seen ciphertext");
    let mut modified_plaintext_num = bignum::from_bytes(&modified_plaintext);

    let s_inv = bignum::invmod(&s, &modulus);
    modified_plaintext_num *= s_inv;
    modified_plaintext_num %= &modulus;

    bignum::to_bytes(&modified_plaintext_num)
}

mod secret {
    use cryptopals::{rsa, sha256};
    use rug::Integer;
    use std::collections::HashSet;

    pub struct Oracle {
        public_key: rsa::PublicKey,
        private_key: rsa::PrivateKey,
        seen_messages: HashSet<Vec<u8>>,
    }

    pub fn new_oracle() -> Oracle {
        let (public_key, private_key) = rsa::keygen(1024, Integer::from(65537));
        let seen_messages = HashSet::new();

        Oracle {
            public_key,
            private_key,
            seen_messages,
        }
    }

    impl Oracle {
        pub fn encrypt(&self, message: &[u8]) -> Vec<u8> {
            rsa::encrypt(&self.public_key, &message)
        }

        pub fn public_key(&self) -> &rsa::PublicKey {
            &self.public_key
        }

        pub fn decrypt(&mut self, ciphertext: &[u8]) -> Option<Vec<u8>> {
            let hash = sha256::sha256(&ciphertext);
            if self.seen_messages.contains(&hash) {
                return None;
            }

            self.seen_messages.insert(hash);
            let decrypted = rsa::decrypt(&self.private_key, &ciphertext);
            Some(decrypted)
        }
    }
}
