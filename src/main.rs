
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

use xor_cipher::break_rep_key_xor;

fn main() {
    let bytes1 = b"0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272
    a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f!";
    let res = break_rep_key_xor(bytes1);
    println!("{:?}", res);
}