/// Slice the length of the bytes array into 32bytes
pub fn element_encoder(v: &[u8]) -> [u8; 32] {
    let mut output = [0u8; 32];
    output.iter_mut().zip(v).for_each(|(b1, b2)| *b1 = *b2);
    output
}

/// Slice the length of bytes array into 4 bytes
pub fn bytes4_encoder(v: &[u8]) -> [u8; 4] {
    let mut output = [0u8; 4];
    output.iter_mut().zip(v).for_each(|(b1, b2)| *b1 = *b2);
    output
}

/// Truncate and pad 256 bit slice
pub fn truncate_and_pad(t: &[u8]) -> Vec<u8> {
    let mut truncated_bytes = t[..20].to_vec();
    truncated_bytes.extend_from_slice(&[0u8; 12]);
    truncated_bytes
}
