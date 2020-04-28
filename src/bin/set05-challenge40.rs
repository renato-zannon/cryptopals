use rug::{Assign, Integer};

use cryptopals::{bignum, prelude::*, quote, rsa};

fn main() {
    let message = quote::random();

    let (pub1, c1) = encrypt_with_new_key(message.as_bytes());
    let (pub2, c2) = encrypt_with_new_key(message.as_bytes());
    let (pub3, c3) = encrypt_with_new_key(message.as_bytes());

    let mut solution = find_solution(&[
        (&c1, &pub1.modulus),
        (&c2, &pub2.modulus),
        (&c3, &pub3.modulus),
    ]);

    (&mut solution).root_mut(3);
    let decrypted_bytes = bignum::to_bytes(&solution);
    let decrypted_string = String::from_utf8_lossy(&decrypted_bytes);

    println!("Decrypted message: {}", decrypted_string);
    println!(
        "{} message matches original",
        check_mark(decrypted_string == message)
    );
}

fn encrypt_with_new_key(message: &[u8]) -> (rsa::PublicKey, Integer) {
    let (public_key, _) = rsa::keygen(1024, Integer::from(3));
    let encrypted = rsa::encrypt(&public_key, message);
    let encrypted_integer = bignum::from_bytes(&encrypted);

    (public_key, encrypted_integer)
}

// find solution for:
//  x ≡ a1 mod n1
//  x ≡ a2 mod n2
fn find_solution(pairs: &[(&Integer, &Integer)]) -> Integer {
    let mut result = Integer::new();

    let mut mod_multiple = Integer::from(1);
    for &(_, n) in pairs {
        mod_multiple *= n;
    }

    let mut remaining_mod = Integer::new();

    for &(a, n) in pairs {
        remaining_mod.assign(&mod_multiple);
        remaining_mod /= n;

        let s = bignum::invmod(&remaining_mod, &n);

        remaining_mod *= s;
        remaining_mod *= a;

        result += &remaining_mod;
    }

    result %= mod_multiple;
    result
}
