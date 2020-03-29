pub fn hex_to_base64(source: &str) -> String {
    bytes_to_base64(&hex_to_bytes(source))
}

pub fn hex_to_bytes(source: &str) -> Vec<u8> {
    let chars: Vec<_> = source.chars().collect();
    let mut bytes: Vec<u8> = Vec::with_capacity(chars.len() / 2);

    for index in (0..chars.len()).step_by(2) {
        let chr1 = hex_char_to_byte(chars[index]);
        let chr2 = hex_char_to_byte(chars[index + 1]);

        let byte = (chr1 << 4) + chr2;
        bytes.push(byte);
    }

    bytes
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
