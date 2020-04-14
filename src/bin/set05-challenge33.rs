use cryptopals::{dh, encoding::bytes_to_hex, utils::check_mark};

fn main() {
    let parameters = dh::Parameters::default();

    let (public_key_a, private_key_a) = parameters.generate_keypair();
    let (public_key_b, private_key_b) = parameters.generate_keypair();

    let session_key_a = parameters.derive_session_key(&public_key_b, &private_key_a);
    println!(
        "Generated session key using priv A + pub B: {}",
        bytes_to_hex(&session_key_a.to_aes_key())
    );

    let session_key_b = parameters.derive_session_key(&public_key_a, &private_key_b);
    println!(
        "Generated session key using priv B + pub A: {}",
        bytes_to_hex(&session_key_b.to_aes_key())
    );

    println!(
        "Keys match {}",
        check_mark(session_key_a.to_aes_key() == session_key_b.to_aes_key())
    );
}
