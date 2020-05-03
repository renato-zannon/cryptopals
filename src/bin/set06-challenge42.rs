use cryptopals::{bignum, prelude::*, rsa, sha1::sha1};

const MESSAGE: &[u8] = b"hi mom";

fn main() {
    let message_hash = sha1(MESSAGE);
    let signer = secret::Signer::new();

    let mod_size = signer.public_key().modulus.significant_digits::<u8>();

    let mut target_signed = vec![0x00, 0x01, 0x00];
    target_signed.extend_from_slice(rsa::SHA1_ASN1_MARKER);
    target_signed.extend_from_slice(&message_hash);
    target_signed.resize(mod_size, 0xff);

    let mut forged_sig_num = bignum::from_bytes(&target_signed);
    forged_sig_num.root_mut(3);
    let forged_sig = bignum::to_bytes(&forged_sig_num);

    println!(
        "{} Forged signature is accepted",
        check_mark(signer.verify_signature(MESSAGE, &forged_sig))
    );
}

mod secret {
    use cryptopals::{bignum, rsa, sha1::sha1};
    use rug::Integer;

    pub struct Signer {
        public_key: rsa::PublicKey,

        #[allow(dead_code)]
        private_key: rsa::PrivateKey,
    }

    impl Signer {
        pub fn new() -> Self {
            let (public_key, private_key) = rsa::keygen(1024, Integer::from(3));

            Self {
                public_key,
                private_key,
            }
        }

        pub fn public_key(&self) -> &rsa::PublicKey {
            &self.public_key
        }

        pub fn verify_signature(&self, message: &[u8], signature: &[u8]) -> bool {
            let signed_bytes = self.to_signed_bytes(signature);

            let mut sig_iter = signed_bytes.iter();

            // We ignore the initial 0x00 because it is always lost in the
            // number -> bytes conversion since we are using Big Endian
            if sig_iter.next() != Some(&0x01) {
                return false;
            }

            loop {
                match sig_iter.next() {
                    Some(0x00) => break,
                    Some(0xff) => continue,
                    _ => return false,
                }
            }

            // verify ASN.1 marker
            {
                let marker_matches = sig_iter
                    .by_ref()
                    .take(rsa::SHA1_ASN1_MARKER.len())
                    .zip(rsa::SHA1_ASN1_MARKER)
                    .all(|(b1, b2)| b1 == b2);

                if !marker_matches {
                    return false;
                }
            }

            // verify message hash
            {
                let message_hash = sha1(&message);
                let hash_matches = sig_iter
                    .by_ref()
                    .take(message_hash.len())
                    .zip(&message_hash)
                    .all(|(b1, b2)| b1 == b2);

                if !hash_matches {
                    return false;
                }
            }

            // NOTE: here's the (intentional) bug. At this point, the remaining length of the
            // signature should have been verified to be 0
            //
            // A version without this bug would be:
            //   return sig_iter.next().is_none();

            true
        }

        fn to_signed_bytes(&self, signature: &[u8]) -> Vec<u8> {
            let signature_num = bignum::from_bytes(signature);
            let signed = bignum::modexp(
                &signature_num,
                &self.public_key.exponent,
                &self.public_key.modulus,
            );

            bignum::to_bytes(&signed)
        }
    }
}
