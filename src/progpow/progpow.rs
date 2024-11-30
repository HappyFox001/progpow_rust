use crate::keccak::f800long::keccak_f800_long;
use crate::keccak::f800short::keccak_f800_short;

use crate::basic_algorithm::{
    fill_mix, fnv1a, higher32, lower32, progpow_loop, PROGPOW_CACHE_BYTES, PROGPOW_CACHE_WORDS,
    PROGPOW_CNT_CACHE, PROGPOW_CNT_DAG, PROGPOW_CNT_MATH, PROGPOW_DAG_LOADS, PROGPOW_LANES,
    PROGPOW_MIX_BYTES, PROGPOW_PERIOD_LENGTH, PROGPOW_REGS,
};
use byteorder::{ByteOrder, LittleEndian};

/// Implements the ProgPoW hashing algorithm.
///
/// This function computes the ProgPoW hash for the provided inputs, including
/// the `hash`, `nonce`, `size`, and `block_number`. It leverages the Keccak-f800
/// hashing and multiple rounds of mathematical and memory operations.
///
/// # Arguments
///
/// * `hash` - A byte slice representing the initial hash value (typically 32 bytes).
/// * `nonce` - A 64-bit nonce used to vary the output.
/// * `size` - The size of the dataset.
/// * `block_number` - The block number associated with this computation.
/// * `c_dag` - The compressed directed acyclic graph (DAG) used for the hash computation.
/// * `lookup` - A function to retrieve memory segments based on an index.
///
/// # Returns
///
/// A tuple containing:
/// 1. `mix_hash` - A vector of 32 bytes representing the mix hash.
/// 2. `final_hash` - A vector of 32 bytes representing the final hash.
///
/// # Notes
///
/// - This function is a critical part of the Proof of Work (PoW) algorithm for
/// blockchain mining and is designed to be GPU-friendly.
pub fn progpow(
    hash: &[u8],
    nonce: u64,
    size: u64,
    block_number: u64,
    c_dag: &[u32],
    lookup: &dyn Fn(u32) -> Vec<u8>,
) -> (Vec<u8>, Vec<u8>) {
    let mut mix = [[0u32; PROGPOW_REGS]; PROGPOW_LANES]; // Initialize mix registers.
    let mut lane_results = [0u32; PROGPOW_LANES]; // Store results per lane.
    let mut result = [0u32; 8]; // Final result array.

    // Compute the initial seed using Keccak-f800 short hash.
    let seed = keccak_f800_short(hash, nonce, &mut result);

    // Initialize the mix for each lane using the seed.
    for lane in 0..PROGPOW_LANES {
        mix[lane] = fill_mix(seed, lane as u32);
    }

    // Compute the period based on the block number and PROGPOW_PERIOD_LENGTH.
    let period = block_number / PROGPOW_PERIOD_LENGTH;

    // Execute the ProgPoW loop `PROGPOW_CNT_DAG` times.
    for l in 0..PROGPOW_CNT_DAG {
        progpow_loop(
            period,
            l as u32,
            &mut mix,
            lookup,
            c_dag,
            (size / PROGPOW_MIX_BYTES as u64) as u32,
        );
    }

    // Reduce the mix data to a single result per lane.
    for lane in 0..PROGPOW_LANES {
        lane_results[lane] = 0x811c9dc5; // Initialize with FNV offset basis.
        for i in 0..PROGPOW_REGS {
            fnv1a(&mut lane_results[lane], mix[lane][i]); // Apply FNV-1a hash.
        }
    }

    // Combine lane results into the final result array.
    for i in 0..8 {
        result[i] = 0x811c9dc5; // Initialize each result element with FNV offset basis.
    }
    for lane in 0..PROGPOW_LANES {
        fnv1a(&mut result[lane % 8], lane_results[lane]); // Apply FNV-1a reduction.
    }

    // Compute the final hash using Keccak-f800 long hash.
    let final_hash = keccak_f800_long(hash, seed, &result);

    // Convert the `result` array to a mix hash (32 bytes).
    let mut mix_hash = vec![0u8; 8 * 4];
    for i in 0..8 {
        LittleEndian::write_u32(&mut mix_hash[i * 4..], result[i]);
    }

    // Return the mix hash and final hash.
    (mix_hash, final_hash)
}
