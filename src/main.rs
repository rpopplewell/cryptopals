
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

use xor_cipher::{rep_key_xor, character_frequency_score};

//CHALLENGE 5 Implement repeating-key XOR
// fn main() {
//     let input_string = "Burning 'em, if you ain't quick and nimble I go crazy when I hear a cymbal".as_bytes();
//     let key = "ICE".as_bytes();

//     let encrypted = hex::encode(rep_key_xor(&key, &input_string));
//     println!("{}", encrypted);
// }

fn main() {
    let bytes1 = b"zwijrioq!";
    // let bytes1 = b"wokka wokka!!!";
    let res = character_frequency_score(bytes1);
    println!("{:?}", res);
}

// fn hex_to_plaintext(input: String) -> Result<String, String> {
//     hex::decode(input).map_err(|e| e.to_string()).
//     and_then(|bytes| String::from_utf8(bytes).
//     map_err(|e| e.to_string()))
// }

// fn hex_to_base64(input: &str) -> Result<String, FromHexError> {
//     let var = hex::decode(input).
//     map(|decoded| general_purpose::STANDARD.encode(decoded));
//     return var;
// }