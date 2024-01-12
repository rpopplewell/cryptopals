
//
// CHALLENGE 3
// mod xor_cypher;
// use hex;
// use std::io;
// use xor_cypher::{break_single_byte_xor, fixed_xor};
//
// m * k = c
// m * k * k = c * k
// m = c * k 
//
// fn main() {
//     let input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
//     let input_text = hex_to_plaintext(input.to_string()).unwrap();

//     let key = break_single_byte_xor(input_text.as_bytes());

//     let key_vec: Vec<u8> = vec![key; input.len()];
//     let ans: String;
//     match fixed_xor(&key_vec, input_text.as_bytes()).and_then(hex_to_plaintext) {
//         Ok(x) => {ans = x}
//         Err(..) => {panic!()}
//     };

//     println!("{ans}");
// }

// CHALLENGE 4
// use xor_cypher::{break_single_byte_xor, compute_score};
// mod xor_cypher;
// fn main() {
//     let dictionary = xor_cypher::load_file_by_line("words.txt");
//     let lines = xor_cypher::load_file_by_line("findit.txt");
//     for line in lines {
//         println!("{line}");
//         let input_text = hex_to_plaintext(line.clone()).unwrap_or("".to_string());
//         let key = break_single_byte_xor(input_text.as_bytes(), &dictionary);
//         let key_vec: Vec<u8> = vec![key; line.len()];
//         let ans: String;
//         match xor_cypher::fixed_xor(&key_vec, &input_text.as_bytes()).and_then(hex_to_plaintext) {
//             Ok(x) => {ans = x}
//             Err(..) => {continue;}
//         };

//     println!("{ans}");
//     }
// }

//CHALLENGE 5 Implement repeating-key XOR
// fn main() {
//     let input_string = "Burning 'em, if you ain't quick and nimble I go crazy when I hear a cymbal".as_bytes();
//     let key = "ICE".as_bytes();

//     let encrypted = hex::encode(rep_key_xor(&key, &input_string));
//     println!("{}", encrypted);
// }

use base64::prelude::*;
use xor_cipher::break_rep_key_xor;

fn main() {
    let input: String = include_str!("../6.txt").replace('\n', "");
    println!("{:?}", input);
    let bytes_res = BASE64_STANDARD.decode(input.as_bytes());
    println!("{:?}", bytes_res);
    match bytes_res {
        Ok(x) => {break_rep_key_xor(x.as_slice())}
        Err(err) => {panic!("{:?}", err)}
    }
}