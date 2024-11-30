//! # ProgPoW Verification Library
//!
//! This library provides a Rust implementation of ProgPoW (Proof of Work for Ethereum).
//!
//! ## Note
//! This implementation is based on the [go-ethereum](https://github.com/ethereum/go-ethereum) repository.
//! Specifically, it replicates and validates the behavior of ProgPoW as implemented in `go-ethereum`.
//!
//! ## Features
//! - Keccak-f800 hashing functions
//! - DAG access and caching
//! - Math and memory mixing operations
//!
//! ## Disclaimer
//! This library is intended for educational purposes or verification use cases. It may not be suitable
//! for production mining.

pub mod basic_algorithm;
pub mod keccak {
    pub mod f800long;
    pub mod f800round;
    pub mod f800short;
}
pub mod progpow {
    pub mod progpow;
}

#[cfg(test)]
mod tests {
    use crate::progpow::progpow::progpow;

    #[test]
    fn test_progpow_function() {
        println!("Test started!");
        let mut hash = vec![0u8; 32];
        for i in 0..32 {
            hash[i] = i as u8;
        }
        let nonce: u64 = 0x123456789ABCDEF0;
        let size: u64 = 1024;
        let block_number: u64 = 100;
        let mut c_dag = vec![0u32; 4 * 1024];
        for i in 0..c_dag.len() {
            c_dag[i] = i as u32;
        }

        let lookup = |index: u32| -> Vec<u8> {
            let mut data = vec![0u8; 64];
            for i in 0..data.len() {
                data[i] = (index + i as u32) as u8;
            }
            data
        };

        let (mix_hash, final_hash) = progpow(&hash, nonce, size, block_number, &c_dag, &lookup);

        let expected_mix_hash = vec![
            0x64, 0x12, 0x7f, 0xab, 0xd5, 0x19, 0xac, 0xd7, 0x84, 0x5d, 0x02, 0x60, 0xcf, 0xf4,
            0x37, 0x29, 0xaf, 0x6a, 0xba, 0x3d, 0xd7, 0x92, 0x3a, 0x29, 0xe7, 0x37, 0x15, 0x70,
            0x8b, 0x58, 0x49, 0xa6,
        ];
        let expected_final_hash = vec![
            0x4d, 0x02, 0x7c, 0x72, 0xce, 0xe4, 0x68, 0x9b, 0xa3, 0xd5, 0xfd, 0x16, 0x33, 0x04,
            0xec, 0x6b, 0x96, 0xd9, 0x96, 0xbc, 0xf3, 0x0f, 0xbc, 0x1a, 0x7f, 0x1f, 0x5b, 0xdf,
            0x20, 0x59, 0xcb, 0x59,
        ];

        assert_eq!(mix_hash, expected_mix_hash, "Mix Hash does not match!");
        assert_eq!(
            final_hash, expected_final_hash,
            "Final Hash does not match!"
        );
    }
}
