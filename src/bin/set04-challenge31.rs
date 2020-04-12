use std::iter::{once, repeat};
use std::time::{Duration, Instant};

use futures::prelude::*;
use reqwest::StatusCode;

use cryptopals::prelude::*;

const TARGET_PLAINTEXT: &str = "Hello world!";
const BASE_URL: &str = "http://localhost:3030/test?delay=50";

const SIGNATURE_LEN: usize = 20;

#[tokio::main]
async fn main() -> Result<(), reqwest::Error> {
    let client = reqwest::Client::new();

    let mut known_signature = Vec::with_capacity(20);

    for _ in 0..SIGNATURE_LEN {
        println!("known sig = {}", bytes_to_hex(&known_signature));

        let mut requests = Vec::with_capacity(0xff);

        for byte in 0x00..=0xff {
            let byte_measurement = measure(&known_signature, byte, client.clone());
            requests.push(byte_measurement);
        }

        let measurements: Vec<_> = stream::iter(requests).buffer_unordered(16).collect().await;
        let max = measurements.iter().max_by_key(|m| m.measurement).unwrap();

        known_signature.push(max.byte);
    }

    println!("Deduced signature: {}", bytes_to_hex(&known_signature));
    let verification_request = request_signature(client, &known_signature).await;
    println!(
        "{} Deduced signature is accepted by server",
        check_mark(verification_request.status == StatusCode::OK)
    );

    Ok(())
}

fn measure(
    known_signature: &[u8],
    byte: u8,
    client: reqwest::Client,
) -> impl Future<Output = ByteMeasurement> {
    let signature: Vec<u8> = known_signature
        .iter()
        .copied()
        .chain(once(byte))
        .chain(repeat(0xff))
        .take(SIGNATURE_LEN)
        .collect();

    async move {
        let response = request_signature(client, signature).await;
        let measurement = response.request_duration.as_micros() as u32;

        ByteMeasurement { byte, measurement }
    }
}

struct SignatureResponse {
    request_duration: Duration,
    status: reqwest::StatusCode,
}

async fn request_signature<V>(client: reqwest::Client, signature: V) -> SignatureResponse
where
    V: AsRef<[u8]>,
{
    let start = Instant::now();

    let response = client
        .get(BASE_URL)
        .query(&[("filename", TARGET_PLAINTEXT)])
        .query(&[("signature", bytes_to_hex(signature.as_ref()))])
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .unwrap();

    let request_duration = start.elapsed();

    SignatureResponse {
        request_duration,
        status: response.status(),
    }
}

#[derive(Hash, Debug, Clone, Ord, PartialOrd, Eq, PartialEq)]
struct ByteMeasurement {
    measurement: u32,
    byte: u8,
}
