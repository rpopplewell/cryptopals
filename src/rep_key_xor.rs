pub fn fixed_xor(bytes1: &[u8], bytes2: &[u8]) -> Vec<u8> {
    let ans = bytes1.iter().zip(bytes2.iter()).
    map(|(&x1, &x2)| x1 ^ x2).collect::<Vec<u8>>();
    return ans;
}

pub fn rep_key_xor(key: &[u8], message: &[u8]) -> Vec<u8> {
    let repeated_key = key.iter().cycle().take(message.len()).cloned().collect::<Vec<u8>>();
    fixed_xor(&repeated_key, message)
}