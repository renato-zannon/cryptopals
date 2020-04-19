use lazy_static::lazy_static;
use rand::{seq::SliceRandom, thread_rng};
use serde_derive::Deserialize;

lazy_static! {
    static ref QUOTES: Vec<Quote> = load_quotes();
}

pub fn random() -> String {
    QUOTES.choose(&mut thread_rng()).unwrap().format()
}

fn load_quotes() -> Vec<Quote> {
    use std::fs;
    use std::io::BufReader;

    let quotes_file = BufReader::new(fs::File::open("data/quotes.json").unwrap());
    serde_json::from_reader(quotes_file).unwrap()
}

#[derive(Deserialize)]
struct Quote {
    content: String,
    author: String,
}

impl Quote {
    fn format(&self) -> String {
        format!("\"{}\" - {}", self.content, self.author)
    }
}
