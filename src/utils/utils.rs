use base64;
use hex;
extern crate ordered_float;

pub trait XOR {
    fn xor(&self, _: &Self) -> Vec<u8>;
    fn xor_inplace(&mut self, _: &Self);
}

impl XOR for [u8] {
    fn xor(&self, t: &[u8]) -> Vec<u8> {
        let mut result = self.to_vec();
        result[..].xor_inplace(t);
        result
    }

    fn xor_inplace(&mut self, t: &[u8]) {
        for chunk in self.chunks_mut(t.len()) {
            let len = chunk.len();
            for (c, &d) in chunk.iter_mut().zip(t[..len].iter()) {
                *c ^= d;
            }
        }
    }
}

fn from_hex(s: &str) -> Result<Vec<u8>, hex::FromHexError> {
    hex::decode(s)
}

fn from_base64(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    base64::decode(s)
}

fn to_base64(input: Vec<u8>) -> String {
    base64::encode(input)
}

#[derive(Debug, Clone)]
struct FixedXorError;

impl std::fmt::Display for FixedXorError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "invalid length")
    }
}

// chi-squared frequency analysis
fn frequency_score(input: &[u8]) -> f32 {
    if !input.is_ascii() || input.iter().any(|&c| (c < 0x20 || c == 0x7F) && c != b'\n') {
        return std::f32::MAX;
    }

    let mut char_count: std::collections::HashMap<u8, f32> = std::collections::HashMap::new();

    for &c in input.iter() {
        if c < 0x20 || c == 0x7F {
            continue;
        }
        let key = if (c >= 0x41 && c <= 0x5A) || (c >= 0x61 && c <= 0x7A) {
            c.to_ascii_lowercase()
        } else if c == b' ' || c == b'\t' {
            b' '
        } else {
            b'.'
        };

        let count = char_count.entry(key).or_insert(0f32);
        *count += 1f32;
    }

    char_count.iter().fold(0f32, |res, (letter, score)| {
        let expected =
            (crate::utils::frequency::letter_frequency((*letter as char).to_ascii_lowercase())
                / 100f32)
                * input.len() as f32;
        let actual = score;
        res + (expected - actual).powi(2)
    })
}

fn crack_single_xor(input: &[u8]) -> u8 {
    (0u8..255)
        .min_by_key(|&u| ordered_float::OrderedFloat(frequency_score(&input.xor(&[u]))))
        .unwrap()
}

fn compute_normalized_hamming_distance(input: &[u8], keysize: usize) -> f32 {
    let chunks: Vec<&[u8]> = input.chunks(keysize).take(4).collect();
    let mut distance = 0f32;
    for i in 0..4 {
        for j in i..4 {
            distance += hamming_distance(chunks[i], chunks[j]) as f32;
        }
    }

    distance / keysize as f32
}

fn transposed_blocks(input: &[u8], size: usize) -> Vec<Vec<u8>> {
    let mut transposed_blocks: Vec<Vec<u8>> = (0..size).map(|_| Vec::new()).collect();
    for block in input.chunks(size) {
        for (&u, bt) in block.iter().zip(transposed_blocks.iter_mut()) {
            bt.push(u);
        }
    }
    transposed_blocks
}

fn crack_repeating_xor(ciphertext: Vec<u8>) -> Vec<u8> {
    let count = 3;
    let mut distances: Vec<(usize, u32)> = (2..40)
        .map(|keysize| {
            (
                keysize,
                (100f32 * compute_normalized_hamming_distance(&ciphertext, keysize)) as u32,
            )
        })
        .collect();

    distances.sort_by(|&(_, s), &(_, t)| s.cmp(&t));
    let candidates: Vec<usize> = distances.iter().take(count).map(|x| x.0).collect();

    candidates
        .iter()
        .map(|&size| {
            transposed_blocks(&ciphertext, size)
                .iter()
                .map(|b| crack_single_xor(b))
                .collect::<Vec<u8>>()
        })
        .min_by_key(|key| ordered_float::OrderedFloat(frequency_score(&ciphertext.xor(key))))
        .unwrap()
}

pub fn hamming_distance(a: &[u8], b: &[u8]) -> u32 {
    let mut counter: u32 = 0;

    for (char_a, char_b) in a.iter().zip(b.iter()) {
        counter += u32_hamming_distance(*char_a as u32, *char_b as u32)
    }

    return counter;
}

fn u32_hamming_distance(a: u32, b: u32) -> u32 {
    let mut counter: u32 = 0;

    let mut value: u32 = a ^ b;
    loop {
        if value <= 0 {
            break;
        }

        if (value & 1) > 0 {
            counter += 1;
        }

        value = value >> 1;
    }

    return counter;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, BufRead};

    #[test]
    fn convert_hex_to_base64_challenge() {
        // Convert hex to base64
        // https://cryptopals.com/sets/1/challenges/1
        let buf = from_hex("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d").unwrap();
        assert_eq!(
            "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",
            to_base64(buf)
        );
    }

    #[test]
    fn fixed_xor_challenge() {
        // Fixed XOR
        // https://cryptopals.com/sets/1/challenges/2
        let a = from_hex("1c0111001f010100061a024b53535009181c").unwrap();
        let b = from_hex("686974207468652062756c6c277320657965").unwrap();
        let res = a.xor(&b);
        assert_eq!("746865206b696420646f6e277420706c6179", hex::encode(res));
    }

    #[test]
    fn single_byte_xor_challenge() {
        // Single-byte XOR cipher
        // https://cryptopals.com/sets/1/challenges/3
        let input =
            from_hex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
                .unwrap();
        let key = crack_single_xor(&input);
        assert_eq!(
            "Cooking MC's like a pound of bacon".as_bytes(),
            &input.xor(&[key])
        );
    }

    #[test]
    fn detect_single_char_xor_challenge() {
        // Detect single-character XOR
        // https://cryptopals.com/sets/1/challenges/4
        let mut d = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        d.push("tests/challenge_1_4");
        let file = std::fs::File::open(d).unwrap();
        let lines = std::io::BufReader::new(file).lines();

        let mut best_score: f32 = std::f32::MAX;
        let mut secret_msg: String = String::new();

        for line in lines {
            if let Ok(ip) = line {
                let input = from_hex(&ip).unwrap();
                let key = crack_single_xor(&input);
                let score: f32 = frequency_score(&input.xor(&[key]));
                if score < best_score {
                    best_score = score;
                    secret_msg = String::from_utf8_lossy(&input.xor(&[key])).into_owned();
                }
            }
        }
        assert_eq!("Now that the party is jumping\n", secret_msg);
    }

    #[test]
    fn repeating_xor_challenge() {
        // Implement repeating-key XOR
        // https://cryptopals.com/sets/1/challenges/5
        let input = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
            .as_bytes();
        let res = hex::encode(input.xor("ICE".as_bytes()));
        assert_eq!("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f", res);
    }

    #[test]
    fn hamming_distance_challenge() {
        assert_eq!(
            37,
            hamming_distance("this is a test".as_bytes(), "wokka wokka!!!".as_bytes())
        );
    }

    #[test]
    fn repeating_key_xor_challenge() {
        // Break repeating-key XOR
        // https://cryptopals.com/sets/1/challenges/6
        let mut d = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        d.push("tests/challenge_1_6");
        let body = std::fs::read_to_string(d).unwrap();
        let buf = from_base64(&body).unwrap();
        let key = crack_repeating_xor(buf);
        assert_eq!("Terminator X: Bring the noise".as_bytes(), key);
    }
}
