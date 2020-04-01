use std::iter::repeat;

use cryptopals::encoding::block_pretty_print;

// "email=&uid=10&role=user".length == 23

const BLOCK_SIZE: usize = 16;

fn main() {
    let oracle = secret::Oracle::new();

    let admin_ciphertext = {
        // with this, "admin" followed by 11 0x0b bytes (pkcs7 padding to complete the block) will
        // on the 2nd block
        let payload: String = repeat(' ')
            .take(10)
            .chain("admin".chars())
            .chain(repeat(0x0b as char).take(11))
            .collect();

        let ciphertext = oracle.profile_for(&payload);
        println!("'admin' ciphertext:\n{}", block_pretty_print(&ciphertext));

        ciphertext[BLOCK_SIZE..BLOCK_SIZE * 2].to_vec()
    };

    // with this email, everything except the final "user" part is in the first 2 blocks
    let encrypted_profile = oracle.profile_for("hey@gmail.com");
    println!(
        "Legitimate profile:\n{}",
        block_pretty_print(&encrypted_profile)
    );

    let forged_profile: Vec<u8> = encrypted_profile
        .into_iter()
        .take(BLOCK_SIZE * 2)
        .chain(admin_ciphertext)
        .collect();
    println!("Forged profile:\n{}", block_pretty_print(&forged_profile));

    let decoded = oracle.parse_profile(&forged_profile);
    println!("Decoded profile: {:?}", decoded);
}

mod secret {
    use rand::prelude::*;
    use std::collections::HashMap;

    use super::BLOCK_SIZE;
    use cryptopals::aes;

    pub struct Oracle {
        key: [u8; BLOCK_SIZE],
    }

    impl Oracle {
        pub fn new() -> Oracle {
            Oracle {
                key: thread_rng().gen(),
            }
        }

        pub fn profile_for(&self, email: &str) -> Vec<u8> {
            let encoded_profile = profile_for(email);

            aes::aes_128_ecb_encrypt(encoded_profile.as_bytes(), &self.key, true)
        }

        pub fn parse_profile(&self, encrypted_profile: &[u8]) -> Option<HashMap<String, String>> {
            let plaintext = aes::aes_128_ecb_decrypt(encrypted_profile, &self.key, true);

            let string_plaintext = String::from_utf8(plaintext).ok()?;
            Some(parse_kv(&string_plaintext))
        }
    }

    fn profile_for(email: &str) -> String {
        let filtered_email: String = email
            .chars()
            .filter(|&chr| chr != '&' && chr != '=')
            .collect();

        format!("email={}&uid=10&role=user", filtered_email)
    }

    fn parse_kv(s: &str) -> HashMap<String, String> {
        let mut result = HashMap::new();

        let mut remaining = s;
        while remaining.len() > 0 {
            if let Some((key, value, end_index)) = extract_next_kv(remaining) {
                remaining = &remaining[(end_index + 1).min(remaining.len())..];
                result.insert(key.to_string(), value.to_string());
            } else {
                break;
            }
        }

        result
    }

    fn extract_next_kv(s: &str) -> Option<(&str, &str, usize)> {
        let equal_index = s.find('=')?;
        let value_end = s.find('&').unwrap_or(s.len());

        Some((
            &s[0..equal_index],
            &s[equal_index + 1..value_end],
            value_end,
        ))
    }

    #[test]
    fn test_profile_for_email() {
        let encoded = profile_for("hello@gmail.com");
        let decoded = parse_kv(&encoded);

        assert_eq!(decoded["email"], "hello@gmail.com");
        assert_eq!(decoded["uid"], "10");
        assert_eq!(decoded["role"], "user");
    }

    #[test]
    fn test_profile_for_email_metacharacters() {
        let encoded = profile_for("hello@gmail.com&role=admin");
        let decoded = parse_kv(&encoded);

        assert_eq!(decoded["email"], "hello@gmail.comroleadmin");
        assert_eq!(decoded["uid"], "10");
        assert_eq!(decoded["role"], "user");
    }
}
