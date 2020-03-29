use cryptopals::padding::pkcs7_pad;

const PLAINTEXT: &'static [u8] = b"YELLOW SUBMARINE";

fn main() {
    println!("{:?}", String::from_utf8(pkcs7_pad(PLAINTEXT, 20)));
}
