use hex;
use base64;

fn from_hex(s :&str) -> Result<Vec<u8>, hex::FromHexError> {
    hex::decode(s)
}

fn to_base64(input: Vec<u8>) -> String {
    base64::encode(input)
}


#[derive(Debug, Clone)]
struct FixedXorError;

impl std::fmt::Display for FixedXorError {
    fn fmt(&self, f: &mut std::fmt::Formatter) ->std::fmt::Result {
        write!(f, "invalid length")
    }
}

fn fixed_xor(a: Vec<u8>, b: Vec<u8>) -> Result<Vec<u8>, FixedXorError> {
    if a.len() != b.len() {
        return Err(FixedXorError);
    }

    let mut res = Vec::new();

    for i in 0..a.len() {
        res.push(a[i] ^ b[i])
    }

    Ok(res)
}

fn single_xor(input: &mut Vec<u8>, ch: u8) {
    for i in 0..input.len() {
        input[i] ^= ch;
    }
}

pub fn xor(input: &[u8], key: &[u8]) -> Vec<u8> {
    let mut res = Vec::new();
    let mut key_index :usize = 0;
    for i in 0..input.len() {
        if key_index >= key.len() {
            key_index = 0;
        }
        res.push(input[i] ^ key[key_index]);

        key_index += 1;
    }

    res
}

fn crack_single_xor(input: &mut Vec<u8>) -> (String, f32) {
    let mut score: f32 = 0.0;
    let mut secret_msg: String = String::from("");

    for i in 0..255 {
        let mut res = input.clone();
        single_xor(&mut res, i);

        let res = String::from_utf8_lossy(&res).into_owned();

        // Get the english language score for each input!
        let mut freq_score: f32 = 0.0;
        for letter in res.chars() {
            let freq = crate::utils::frequency::letter_frequency(letter);
            freq_score += &freq;
        }

        if freq_score > score {
            score = freq_score;
            secret_msg = res.to_string();
        }
    }

    (secret_msg, score)
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
        assert_eq!("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",to_base64(buf));
    }

    #[test]
    fn fixed_xor_challenge() {
        // Fixed XOR
        // https://cryptopals.com/sets/1/challenges/2
        let a = from_hex("1c0111001f010100061a024b53535009181c").unwrap();
        let b = from_hex("686974207468652062756c6c277320657965").unwrap();
        let res = fixed_xor(a,b).unwrap();
        assert_eq!("746865206b696420646f6e277420706c6179", hex::encode(res));
    }

    #[test]
    fn single_byte_xor_challenge() {
        // Single-byte XOR cipher
        // https://cryptopals.com/sets/1/challenges/3
        let mut input = from_hex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736").unwrap();
        assert_eq!("Cooking MC's like a pound of bacon", crack_single_xor(&mut input).0);
    }

    #[test]
    fn detect_single_char_xor_challenge() {
        // Detect single-character XOR
        // https://cryptopals.com/sets/1/challenges/4
        let mut d = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        d.push("tests/challenge_1_4");
        let file = std::fs::File::open(d).unwrap();
        let lines = std::io::BufReader::new(file).lines();

        let mut best_score: f32 = 0.0;
        let mut secret_msg: String = String::from("");

        for line in lines {
            if let Ok(ip) = line {
                let mut input = from_hex(&ip).unwrap();
                let (res, score) = crack_single_xor(&mut input);
                if score > best_score {
                    best_score = score;
                    secret_msg = res;
                }
            }
        }
        assert_eq!("Now that the party is jumping\n", secret_msg);
    }

    #[test]
    fn repeating_xor_challenge() {
        // Implement repeating-key XOR
        // https://cryptopals.com/sets/1/challenges/5
        let mut input = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal".as_bytes();
        let res = hex::encode(xor(input, "ICE".as_bytes()));
        assert_eq!("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f", res);
    }
}