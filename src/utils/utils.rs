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

#[cfg(test)]
mod tests {
    use super::*;

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
}