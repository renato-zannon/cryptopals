pub fn hex_to_base64(source: &str) -> String {
    bytes_to_base64(&hex_to_bytes(source))
}

pub fn block_pretty_print(bytes: &[u8]) -> String {
    use crate::string_wrap::StringWrap;
    format!("{}", bytes_to_hex(bytes).hex_pp(32))
}

pub fn hex_to_bytes(source: &str) -> Vec<u8> {
    let chars: Vec<_> = source.chars().collect();
    let mut bytes: Vec<u8> = Vec::with_capacity(chars.len() / 2);

    for index in (0..chars.len()).step_by(2) {
        let chr1 = hex_char_to_byte(chars[index]);
        let chr2 = hex_char_to_byte(chars[index + 1]);

        let byte = (chr1 << 4) | chr2;
        bytes.push(byte);
    }

    bytes
}

pub fn base64_to_bytes(source: &str) -> Vec<u8> {
    let chars: Vec<_> = source.chars().filter(|chr| !chr.is_whitespace()).collect();
    let base64len = chars.len();

    if base64len % 4 != 0 {
        panic!("Invalid Base64 string length: {}", base64len);
    }

    let chr = |index| base64_char_to_byte(chars[index]);

    let mut result: Vec<u8> = Vec::with_capacity(base64len * 2 / 3);

    for index in (0..base64len).step_by(4) {
        let n1 = (chr(index) << 2) | (chr(index + 1) >> 4);
        result.push(n1);

        if chars[index + 2] == '=' {
            continue;
        }

        let n2 = (chr(index + 1) << 4) | (chr(index + 2) >> 2);
        result.push(n2);

        if chars[index + 3] == '=' {
            continue;
        }

        let n3 = (chr(index + 2) << 6) | chr(index + 3);
        result.push(n3);
    }

    result
}

const HEX_TABLE: &'static [char] = &[
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
];

pub fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut result = String::with_capacity(bytes.len() * 4 / 3);
    if bytes.len() == 0 {
        return result;
    }

    for byte in bytes {
        let higher = byte >> 4;
        let lower = byte & 0x0f;

        result.push(HEX_TABLE[higher as usize]);
        result.push(HEX_TABLE[lower as usize]);
    }

    result
}

const BASE64_TABLE: &'static [char] = &[
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S',
    'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
    'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4',
    '5', '6', '7', '8', '9', '+', '/',
];

pub fn bytes_to_base64(bytes: &[u8]) -> String {
    let mut result = String::with_capacity(bytes.len() * 4 / 3);
    if bytes.len() == 0 {
        return result;
    }

    let mut index = 0;

    loop {
        let remaining = bytes.len() - index;

        if remaining >= 1 {
            let n1 = bytes[index] >> 2;
            result.push(BASE64_TABLE[n1 as usize]);
        } else {
            break;
        }

        if remaining >= 2 {
            let n2 = ((bytes[index] & 0b00000011) << 4) | (bytes[index + 1] >> 4);
            result.push(BASE64_TABLE[n2 as usize]);
        } else {
            let n2 = (bytes[index] & 0b00000011) << 4;
            result.push(BASE64_TABLE[n2 as usize]);
            result.push('=');
            result.push('=');
            break;
        }

        if remaining >= 3 {
            let n3 = ((bytes[index + 1] & 0b00001111) << 2) | (bytes[index + 2] >> 6);
            let n4 = bytes[index + 2] & 0b00111111;

            result.push(BASE64_TABLE[n3 as usize]);
            result.push(BASE64_TABLE[n4 as usize]);
        } else {
            let n3 = (bytes[index + 1] & 0b00001111) << 2;
            result.push(BASE64_TABLE[n3 as usize]);
            result.push('=');
            break;
        }

        index += 3;
    }

    result
}

fn hex_char_to_byte(chr: char) -> u8 {
    match chr {
        '0'..='9' => (chr as u8) - ('0' as u8),
        'a'..='f' => (chr as u8) - ('a' as u8) + 10,
        _ => panic!("Invalid character on hex string: {}", chr),
    }
}

fn base64_char_to_byte(chr: char) -> u8 {
    match chr {
        'A'..='Z' => (chr as u8) - ('A' as u8),
        'a'..='z' => (chr as u8) - ('a' as u8) + 26,
        '0'..='9' => (chr as u8) - ('0' as u8) + 52,
        '+' => 62,
        '/' => 63,
        _ => panic!("Invalid Base64 character {:?}", chr),
    }
}

#[test]
fn test_decode_base64() {
    assert_eq!(
        base64_to_bytes("YW55IGNhcm5hbCBwbGVhc3VyZS4="),
        b"any carnal pleasure."
    );

    assert_eq!(base64_to_bytes("TWFu"), &[77, 97, 110]);
    assert_eq!(base64_to_bytes("TWE="), &[77, 97]);
    assert_eq!(base64_to_bytes("TQ=="), &[77]);
}

#[test]
fn test_decode_wrapped_base64() {
    let encoded = "\
TWFuIGlzIGRpc3Rpbmd1aXNoZWQsIG5vdCBvbmx5IGJ5IGhpcyByZWFzb24sIGJ1dCBieSB0aGlz
IHNpbmd1bGFyIHBhc3Npb24gZnJvbSBvdGhlciBhbmltYWxzLCB3aGljaCBpcyBhIGx1c3Qgb2Yg
dGhlIG1pbmQsIHRoYXQgYnkgYSBwZXJzZXZlcmFuY2Ugb2YgZGVsaWdodCBpbiB0aGUgY29udGlu
dWVkIGFuZCBpbmRlZmF0aWdhYmxlIGdlbmVyYXRpb24gb2Yga25vd2xlZGdlLCBleGNlZWRzIHRo
ZSBzaG9ydCB2ZWhlbWVuY2Ugb2YgYW55IGNhcm5hbCBwbGVhc3VyZS4=";

    let decoded =
    b"Man is distinguished, not only by his reason, but by this singular passion from other animals, \
which is a lust of the mind, that by a perseverance of delight in the continued and indefatigable \
generation of knowledge, exceeds the short vehemence of any carnal pleasure.";

    assert_eq!(base64_to_bytes(encoded), decoded.as_ref());
}
