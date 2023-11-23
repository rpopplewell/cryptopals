use xor::XOR;
use std::collections::HashSet;
use std::str;
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;

pub fn break_rep_key_xor() {

}

pub fn load_file_by_line(path: &str) -> HashSet<String> {
    let path = Path::new(&path);
    let file = File::open(&path).unwrap();
    let reader = io::BufReader::new(file);

    let mut lines = HashSet::new();

    for line in reader.lines() {
        let word = line.unwrap();
        lines.insert(word);
    }
    
    return lines;
}

pub fn fixed_xor(bytes1: &[u8], bytes2: &[u8]) -> Vec<u8> {
    let ans = bytes1.iter().zip(bytes2.iter()).
    map(|(&x1, &x2)| x1 ^ x2).collect::<Vec<u8>>();
    return ans;
}

pub fn rep_key_xor(key: &[u8], message: &[u8]) -> Vec<u8> {
    let repeated_key = key.iter().cycle().take(message.len()).cloned().collect::<Vec<u8>>();
    fixed_xor(&repeated_key, message)
}

pub fn get_words(v: &[u8]) -> HashSet<String> {
    let cypher_words = str::from_utf8(v).
        map(|x| x.split(" ").collect::<Vec<&str>>()).
        map(|x| x.into_iter().map(|s| s.to_string()).collect::<HashSet<String>>()).unwrap_or(HashSet::from([]));

    return cypher_words;
}

pub fn compute_score(v: &[u8], dict: &HashSet<String>) -> u32 {
    let cypher_words = get_words(v);
    let score: u32 = dict.intersection(&cypher_words).count().try_into().unwrap();
    return score;
}

pub fn break_single_byte_xor(input: &[u8], dictionary: &HashSet<String>) -> u8 {
    (0u8..=255)
        .max_by_key(|&u| compute_score(&input.xor(&[u]), &dictionary))
        .unwrap()
}
