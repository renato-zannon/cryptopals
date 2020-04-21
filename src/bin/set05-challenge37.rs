use rug::Integer;

use cryptopals::{hmac::hmac_sha256, prelude::*, sha256::sha256, srp};

const PASSWORD: &[u8] = b"hunter2";

fn main() {
    let server = build_server(PASSWORD);

    run_with_b_0(&server);
    run_with_b_n(&server);
}

// A '0' client public key makes the server compute SHA256("") for the session key -
// which makes the HMAC guessable given the salt
fn run_with_b_0(server: &srp::Server) {
    let salt = server.salt();
    let session_key = sha256(&[]);
    let hmac = hmac_sha256(&session_key, salt);

    let is_valid = server.verify_session_hmac(&Integer::from(0), &hmac);

    println!(
        "{} server accepts HMAC without the password (A=0)",
        check_mark(is_valid)
    );
}

// A client public key that is a multiple of 'N' makes the server compute SHA256("") for the
// session key - which makes the HMAC guessable given the salt
fn run_with_b_n(server: &srp::Server) {
    let salt = server.salt();
    let session_key = sha256(&[]);
    let hmac = hmac_sha256(&session_key, salt);

    let is_valid = server.verify_session_hmac(&srp::NIST_PRIME, &hmac);

    println!(
        "{} server accepts HMAC without the password (A=N)",
        check_mark(is_valid)
    );
}

fn build_server(password: &[u8]) -> srp::Server {
    let verifier = srp::Verifier::new(password);
    srp::Server::new(verifier)
}
