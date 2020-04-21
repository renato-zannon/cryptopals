use cryptopals::{prelude::*, srp};

const PASSWORD: &[u8] = b"hunter2";
const INVALID_PASSWORD: &[u8] = b"hunter3";

fn main() {
    let server = build_server(PASSWORD);
    let valid_client = srp::Client::new(PASSWORD.to_vec());

    let client_hmac = valid_client.compute_session_hmac(server.salt(), server.public_key());
    let is_valid = server.verify_session_hmac(valid_client.public_key(), &client_hmac);

    println!(
        "{} server accepts client HMAC with correct password",
        check_mark(is_valid)
    );

    let invalid_client = srp::Client::new(INVALID_PASSWORD.to_vec());
    let invalid_client_hmac =
        invalid_client.compute_session_hmac(server.salt(), server.public_key());
    let is_valid = server.verify_session_hmac(invalid_client.public_key(), &invalid_client_hmac);

    println!(
        "{} server rejects client HMAC with invalid password",
        check_mark(!is_valid)
    );
}

fn build_server(password: &[u8]) -> srp::Server {
    let verifier = srp::Verifier::new(password);
    srp::Server::new(verifier)
}
