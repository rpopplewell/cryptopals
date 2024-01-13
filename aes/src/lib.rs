use openssl::symm::{decrypt, Cipher};
use xor_cipher::load_file_by_line;
// use base64::prelude::*;

const KEY: &[u8] = b"YELLOW SUBMARINE";

pub fn aes_128() {
    let input: &str = include_str!("../../07.txt");
    let lines = load_file_by_line("../../07.txt");
    let fmt_input = input.chars().
        map(|s| s.to_string()).
        collect::<Vec<String>>().
        join("");

    println!("{:?}", fmt_input);
    println!("{:?}", lines);

    // let bytes = BASE64_STANDARD.decode()
    // let plaintext = decrypt(Cipher::aes_128_ecb(), KEY, None, &bytes).unwrap();
    // println!("{}", String::from_utf8(plaintext).unwrap())
}