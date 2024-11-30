# ProgPoW Verifier

**ProgPoW Verifier** is a Rust implementation of the ProgPoW (Proof-of-Work) algorithm for Ethereum mining verification. This library is based on the [go-ethereum](https://github.com/ethereum/go-ethereum) implementation of ProgPoW.

## Features

- **Keccak-f800 hashing**: Implements the Keccak-f800 permutation for short and long hashing.
- **ProgPoW loops**: Supports DAG accesses and math operations as defined in the ProgPoW specification.
- **Lightweight random generation**: Uses the KISS99 pseudo-random number generator for consistent results.
- **Verification focus**: Suitable for validating ProgPoW computations.

## Usage

Add this library to your `Cargo.toml`:

```toml
[dependencies]
progpow_verifier = "0.1.0"
