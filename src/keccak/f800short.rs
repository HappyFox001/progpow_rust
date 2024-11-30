use crate::{
    basic_algorithm::{higher32, lower32},
    keccak::f800round::keccak_f800_round,
};

/// Computes a shortened Keccak-f800 hash.
///
/// This function initializes a state array, combines the `header_hash`, `nonce`,
/// and `result` values, performs 21 rounds of the Keccak-f800 permutation,
/// and finally returns the result as a single 64-bit unsigned integer.
///
/// # Arguments
///
/// * `header_hash` - A byte slice representing the header hash (32 bytes expected).
/// * `nonce` - A 64-bit nonce value.
/// * `result` - A slice of 32-bit integers (minimum of 8 elements).
///
/// # Returns
///
/// A `u64` representing the shortened Keccak-f800 hash result.
pub fn keccak_f800_short(header_hash: &[u8], nonce: u64, result: &[u32]) -> u64 {
    let mut st = [0u32; 25]; // Initialize the state array with 25 32-bit integers.

    // Populate the first 8 words of the state array from `header_hash`.
    for i in 0..8 {
        st[i] = (header_hash[4 * i] as u32)
            | ((header_hash[4 * i + 1] as u32) << 8)
            | ((header_hash[4 * i + 2] as u32) << 16)
            | ((header_hash[4 * i + 3] as u32) << 24);
    }

    // Add the lower 32 bits and higher 32 bits of the `nonce` to the state.
    st[8] = lower32(nonce);
    st[9] = higher32(nonce);

    // Add the first 8 elements of the `result` array to the state.
    for i in 0..8 {
        st[10 + i] = result[i];
    }

    // Perform 21 rounds of the Keccak-f800 permutation.
    for r in 0..21 {
        keccak_f800_round(&mut st, r);
    }
    // Perform the 22nd round explicitly (round 21).
    keccak_f800_round(&mut st, 21);

    // Convert the first two words of the state into a single `u64`.
    let mut ret = [0u8; 8];
    ret[4..].copy_from_slice(&st[0].to_be_bytes()); // Use the first state word (big-endian).
    ret[..4].copy_from_slice(&st[1].to_be_bytes()); // Use the second state word (big-endian).

    u64::from_le_bytes(ret) // Return the 64-bit result.
}
