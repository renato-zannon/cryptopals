use rug::Integer;

use cryptopals::{prelude::*, quote, rsa};

fn main() {
    let (public_key, private_key) = rsa::keygen(2048, Integer::from(3));

    let message = quote::random();

    let encrypted = rsa::encrypt(&public_key, message.as_bytes());
    println!("Encrypted message:\n{}", block_pretty_print(&encrypted));

    let decrypted = rsa::decrypt(&private_key, &encrypted);
    println!("Decrypted message: {}", String::from_utf8_lossy(&decrypted));

    println!(
        "{} Decrypted message matches original",
        check_mark(decrypted == message.as_bytes())
    );
}
