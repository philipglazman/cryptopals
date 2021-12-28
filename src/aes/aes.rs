// challenge 7
use openssl::symm::{Cipher, Crypter, Mode};

fn decrypt_aes_128_ecb(ciphertext: &[u8], key: &[u8]) -> Vec<u8> {
    let mut decrypter = Crypter::new(Cipher::aes_128_ecb(), Mode::Decrypt, key, None).unwrap();

    let mut res = vec![0; ciphertext.len() + Cipher::aes_128_ecb().block_size()];

    let mut count = ciphertext
        .chunks(Cipher::aes_128_ecb().block_size())
        .fold(0, |count, block| {
            count + decrypter.update(&block, &mut res[count..]).unwrap()
        });

    count += decrypter.finalize(&mut res[count..]).unwrap();
    res.truncate(count);
    res
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils;
    use std::io::BufRead;

    #[test]
    fn decrypt_aes_ecb_challenge() {
        // AES in ECB mode
        // https://cryptopals.com/sets/1/challenges/7
        let mut d = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        d.push("tests/challenge_1_7");
        let body = std::fs::read_to_string(d).unwrap();
        let buf = utils::from_base64(&body).unwrap();
        let key = b"YELLOW SUBMARINE";
        let res = decrypt_aes_128_ecb(&buf, key);
        let plaintext = "I\'m back and I\'m ringin\' the bell \nA rockin\' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that\'s my DJ Deshay cuttin\' all them Z\'s \nHittin\' hard and the girlies goin\' crazy \nVanilla\'s on the mike, man I\'m not lazy. \n\nI\'m lettin\' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse\'s to the side yellin\', Go Vanilla Go! \n\nSmooth \'cause that\'s the way I will be \nAnd if you don\'t give a damn, then \nWhy you starin\' at me \nSo get off \'cause I control the stage \nThere\'s no dissin\' allowed \nI\'m in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n\' play \n\nStage 2 -- Yea the one ya\' wanna listen to \nIt\'s off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI\'m an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI\'m like Samson -- Samson to Delilah \nThere\'s no denyin\', You can try to hang \nBut you\'ll keep tryin\' to get my style \nOver and over, practice makes perfect \nBut not if you\'re a loafer. \n\nYou\'ll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I\'m comin\' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin\' \nVanilla Ice is sellin\' and you people are buyin\' \n\'Cause why the freaks are jockin\' like Crazy Glue \nMovin\' and groovin\' trying to sing along \nAll through the ghetto groovin\' this here song \nNow you\'re amazed by the VIP posse. \n\nSteppin\' so hard like a German Nazi \nStartled by the bases hittin\' ground \nThere\'s no trippin\' on mine, I\'m just gettin\' down \nSparkamatic, I\'m hangin\' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n\'89 in my time! You, \'90 is my year. \n\nYou\'re weakenin\' fast, YO! and I can tell it \nYour body\'s gettin\' hot, so, so I can smell it \nSo don\'t be mad and don\'t be sad \n\'Cause the lyrics belong to ICE, You can call me Dad \nYou\'re pitchin\' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don\'t be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you\'re dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n";
        assert_eq!(plaintext.as_bytes(), res);
    }

    #[test]
    fn detect_aes_ecb_challenge() {
        // Detect AES in ECB mode
        // https://cryptopals.com/sets/1/challenges/8
        // Each line is a hex-encoded ciphertext.
        // Break apart each line into 16-byte blocks,
        // and see if any of the blocks are identical.
        let mut f = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        f.push("tests/challenge_1_8");
        let file = std::fs::File::open(f).unwrap();
        let mut lines = std::io::BufReader::new(file).lines();

        let dup: Option<String> = loop {
            if let Some(line) = lines.next() {
                let line = line.unwrap();
                let buf = utils::from_hex(&line).unwrap();

                let mut map: std::collections::HashMap<&[u8], usize> =
                    std::collections::HashMap::new();
                for block in buf.chunks(16) {
                    let count = map.entry(block).or_insert(0);
                    *count += 1;
                }

                let dup = map.iter().any(|(_block, count)| count > &1);

                if dup {
                    break Some(line);
                }
            } else {
                break None;
            };
        };

        assert_eq!("d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a", dup.as_ref().unwrap());
    }
}
