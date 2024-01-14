use openssl::symm::{decrypt, Cipher};
use base64::prelude::*;
use std::fs::File;
use std::io::{self, Read};
use std::ops::Sub;
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

pub fn pkcs_7_padding(bytes: &[u8], blocksize: usize) -> Vec<u8> {
    let chunks = bytes.rchunks_exact(blocksize);
    let mut rem = chunks.remainder().to_vec();

    let padding_size = blocksize.sub(rem.len());
    let padding = vec![padding_size as u8; padding_size];
    rem.extend_from_slice(padding.as_slice());

    let mut padded_bytes: Vec<u8> = chunks.flat_map(
        |chunk| chunk.iter().copied()
    ).collect();

    padded_bytes.extend_from_slice(&rem);
    return padded_bytes;
}