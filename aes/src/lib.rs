use openssl::symm::{decrypt, Cipher};
use base64::prelude::*;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

const KEY: &[u8] = b"YELLOW SUBMARINE";

pub fn aes_128(path: String) -> Vec<u8> {
    let mut reader = io::BufReader::new(
        File::open(
            &Path::new(&path)
        ).unwrap()
    );

    let mut buffer = Vec::<u8>::new();

    let _ = reader.read_to_end(&mut buffer);
    let cipher_text = String::from_utf8(buffer).unwrap().replace("\n", "");
    let cipher_bytes = BASE64_STANDARD.decode(cipher_text).unwrap();
    decrypt(Cipher::aes_128_ecb(), KEY, None, &cipher_bytes).unwrap()
}