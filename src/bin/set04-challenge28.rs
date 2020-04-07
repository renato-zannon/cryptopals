use cryptopals::prelude::*;

fn main() {
    let message = b"very important message";
    let mut mac = secret::authenticate(message);

    println!("Message Authentication Code:\n{}", block_pretty_print(&mac));
    println!(
        "Actual MAC verifies: {}",
        check_mark(secret::verify(message, &mac))
    );

    mac[0] ^= 0xFF;

    println!(
        "Tampered MAC is detected: {}",
        check_mark(!secret::verify(message, &mac))
    );
}

mod secret {
    use cryptopals::sha1::sha1;

    const KEY: &[u8] = b"such secret, very MAC";

    pub fn authenticate(message: &[u8]) -> Vec<u8> {
        let mut prefixed = Vec::with_capacity(message.len() + KEY.len());
        prefixed.extend_from_slice(KEY);
        prefixed.extend_from_slice(message);

        sha1(&prefixed)
    }

    pub fn verify(message: &[u8], maybe_mac: &[u8]) -> bool {
        let actual_mac = authenticate(message);

        maybe_mac == actual_mac.as_slice()
    }
}
