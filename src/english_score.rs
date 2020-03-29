const FREQUENCIES: &'static [f64] = &[
    8.167, 1.492, 2.202, 4.253, 12.702, 2.228, 2.015, 6.094, 6.966, 0.153, 1.292, 4.025, 2.406,
    6.749, 7.507, 1.929, 0.095, 5.987, 6.327, 9.356, 2.758, 0.978, 2.560, 0.150, 1.994, 0.077,
];

const PUNCTUATION: &'static [u8] = b" !,.?\"'()@&%";

pub fn english_score(plaintext: &[u8]) -> f64 {
    if plaintext.len() == 0 {
        return 0.0;
    }

    let mut counts = vec![0; FREQUENCIES.len()];
    let mut unexpected_count = 0;

    for &original_byte in plaintext {
        let mut byte = original_byte;

        if byte >= 'A' as u8 && byte <= 'Z' as u8 {
            byte += 32;
        }

        if byte < 'a' as u8 || byte > 'z' as u8 {
            if !PUNCTUATION.contains(&byte) {
                unexpected_count += 1;
            }

            continue;
        }

        let index = byte - ('a' as u8);
        counts[index as usize] += 1;
    }

    let mut score = 100f64;
    let plaintext_len = plaintext.len() as f64;

    for (index, &count) in counts.iter().enumerate() {
        let expected = FREQUENCIES[index];
        let frequency = (100.0 * count as f64) / plaintext_len;

        let diff = (expected - frequency).abs();
        score -= diff;
    }

    score -= unexpected_count as f64;

    score
}
