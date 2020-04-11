use serde_derive::Deserialize;
use warp::http::StatusCode;
use warp::Filter;

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use cryptopals::{encoding::hex_to_bytes, hmac};

#[derive(Deserialize)]
struct Query {
    filename: String,
    signature: String,
    delay: Option<u64>,
}

#[tokio::main]
async fn main() {
    let oracle = Arc::new(Oracle::new());

    let test = warp::path!("test")
        .and(warp::query::<Query>())
        .and_then(move |query: Query| validate_query(oracle.clone(), query));

    warp::serve(test).run(([127, 0, 0, 1], 3030)).await;
}

struct Oracle {
    key: Vec<u8>,
}

impl Oracle {
    fn new() -> Self {
        use rand::{distributions::Standard, thread_rng, Rng};

        let key = thread_rng().sample_iter(Standard).take(128).collect();
        Self { key }
    }

    async fn validate(&self, message: &[u8], signature: &[u8], delay_millis: u64) -> bool {
        let computed_signature = hmac::hmac_sha1(&self.key, message);

        for (b1, b2) in computed_signature.iter().zip(signature) {
            if b1 != b2 {
                return false;
            }

            tokio::time::delay_for(Duration::from_millis(delay_millis)).await
        }

        true
    }
}

async fn validate_query(oracle: Arc<Oracle>, query: Query) -> Result<impl warp::Reply, Infallible> {
    let message = query.filename.as_bytes();
    let signature = &hex_to_bytes(&query.signature);
    let delay = query.delay.unwrap_or(50);

    let result = oracle.validate(message, signature, delay).await;

    if result {
        Ok(StatusCode::OK)
    } else {
        Ok(StatusCode::UNAUTHORIZED)
    }
}
