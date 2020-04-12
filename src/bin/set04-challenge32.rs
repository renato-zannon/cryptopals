use std::collections::HashMap;
use std::iter::{once, repeat};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::prelude::*;
use rand::prelude::*;
use reqwest::StatusCode;

use cryptopals::prelude::*;

const TARGET_PLAINTEXT: &str = "Hello world!";
const BASE_URL: &str = "http://localhost:3030/test?delay=1";

const REPETITIONS: usize = 100;
const SIGNATURE_LEN: usize = 20;

#[tokio::main]
async fn main() -> Result<(), reqwest::Error> {
    let client = reqwest::Client::new();

    let mut known_signature = Vec::with_capacity(20);

    for index in 0..SIGNATURE_LEN {
        println!("known sig = {}", bytes_to_hex(&known_signature));

        let mut requests = Vec::with_capacity(0xff * REPETITIONS);

        for byte in 0x00..=0xff {
            let byte_measurements =
                measure_with_repetitions(&known_signature, byte, client.clone());
            requests.extend(byte_measurements);
        }
        requests.shuffle(&mut thread_rng());

        let measurements: Vec<_> = stream::iter(requests)
            .buffer_unordered(REPETITIONS / 2)
            .collect()
            .await;

        let byte = most_common_byte(&measurements).unwrap_or_else(|| {
            panic!("No byte above deviation threshold for index {}", index);
        });

        known_signature.push(byte);
    }

    println!("Deduced signature: {}", bytes_to_hex(&known_signature));
    let verification_request = request_signature(client, Arc::new(known_signature)).await;
    println!(
        "{} Deduced signature is accepted by server",
        check_mark(verification_request.status == StatusCode::OK)
    );

    Ok(())
}

fn most_common_byte(measurements: &[ByteMeasurement]) -> Option<u8> {
    use statrs::statistics::OrderStatistics;

    let mut durations_per_byte = HashMap::new();

    for m in measurements {
        let durations = durations_per_byte.entry(m.byte).or_insert(vec![]);
        durations.push(m.measurement.as_micros() as f64);
    }

    durations_per_byte
        .iter_mut()
        .map(|(byte, durations)| (byte, durations.percentile(50)))
        .max_by(|(_, m1), (_, m2)| m1.partial_cmp(m2).unwrap())
        .map(|(&byte, _)| byte)
}

fn measure_with_repetitions(
    known_signature: &[u8],
    byte: u8,
    client: reqwest::Client,
) -> impl Iterator<Item = impl Future<Output = ByteMeasurement>> {
    let signature: Vec<u8> = known_signature
        .iter()
        .copied()
        .chain(once(byte))
        .chain(repeat(0xff))
        .take(SIGNATURE_LEN)
        .collect();
    let signature = Arc::new(signature);

    (0..REPETITIONS).map(move |_| {
        let c = client.clone();
        let s = signature.clone();
        let b = byte;

        async move {
            let response = tokio::spawn(request_signature(c, s)).await.unwrap();
            let measurement = response.request_duration;

            ByteMeasurement {
                byte: b,
                measurement,
            }
        }
    })
}

struct SignatureResponse {
    request_duration: Duration,
    status: reqwest::StatusCode,
}

async fn request_signature(client: reqwest::Client, signature: Arc<Vec<u8>>) -> SignatureResponse {
    let request = client
        .get(BASE_URL)
        .query(&[("filename", TARGET_PLAINTEXT)])
        .query(&[("signature", bytes_to_hex(signature.as_ref()))])
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();

    let start = Instant::now();
    let response = client.execute(request).await.unwrap();
    let request_duration = start.elapsed();

    SignatureResponse {
        request_duration,
        status: response.status(),
    }
}

#[derive(Hash, Debug, Clone, Ord, PartialOrd, Eq, PartialEq)]
struct ByteMeasurement {
    measurement: Duration,
    byte: u8,
}
