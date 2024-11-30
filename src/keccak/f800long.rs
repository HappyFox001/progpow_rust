use crate::{
    basic_algorithm::{higher32, lower32},
    keccak::f800round::keccak_f800_round,
};

use byteorder::{ByteOrder, LittleEndian};

/// Computes the Keccak-f800 hash over a longer input.
///
/// This function initializes a state array, combines the `header_hash` and `nonce`
/// with additional results, and applies the Keccak-f800 round function multiple times.
/// Finally, it returns the resulting hash as a 32-byte vector.
///
/// # Arguments
///
/// * `header_hash` - A byte slice representing the header hash (typically 32 bytes).
/// * `nonce` - A 64-bit nonce value.
/// * `result` - A slice of 32-bit integers to be included in the hash computation (minimum 8 elements).
///
/// # Returns
///
/// A `Vec<u8>` representing the 32-byte hash result.
pub fn keccak_f800_long(header_hash: &[u8], nonce: u64, result: &[u32]) -> Vec<u8> {
    let mut st = [0u32; 25]; // Initialize the state array with 25 32-bit integers.

    // Load the first 8 words (32-bit chunks) from the `header_hash` into the state.
    for i in 0..8 {
        st[i] = (header_hash[4 * i] as u32)
            | ((header_hash[4 * i + 1] as u32) << 8)
            | ((header_hash[4 * i + 2] as u32) << 16)
            | ((header_hash[4 * i + 3] as u32) << 24);
    }

    // Add the lower 32 bits and higher 32 bits of the `nonce` to the state.
    st[8] = lower32(nonce);
    st[9] = higher32(nonce);

    // Load the next 8 words from the `result` slice into the state.
    for i in 0..8 {
        st[10 + i] = result[i];
    }

    // Apply the Keccak-f800 round function 22 times.
    for r in 0..=21 {
        keccak_f800_round(&mut st, r);
    }

    // Prepare the final 32-byte output by converting the first 8 words of the state to bytes.
    let mut ret = vec![0u8; 32];
    for i in 0..8 {
        LittleEndian::write_u32(&mut ret[i * 4..], st[i]);
    }

    ret // Return the computed hash as a vector of bytes.
}
