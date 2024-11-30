/// Round constants for Keccak-f800.
/// These constants are used during the `Iota` step of each round.
const KECCAKF_RNDC: [u32; 24] = [
    0x00000001, 0x00008082, 0x0000808a, 0x80008000, 0x0000808b, 0x80000001, 0x80008081, 0x00008009,
    0x0000008a, 0x00000088, 0x80008009, 0x8000000a, 0x8000808b, 0x0000008b, 0x00008089, 0x00008003,
    0x00008002, 0x00000080, 0x0000800a, 0x8000000a, 0x80008081, 0x00008080, 0x80000001, 0x80008008,
];

/// Performs a left rotation on a 32-bit unsigned integer.
///
/// # Arguments
///
/// * `x` - The value to rotate.
/// * `n` - The number of bits to rotate left by.
///
/// # Returns
///
/// The rotated value.
fn rotl32(x: u32, n: u32) -> u32 {
    x.rotate_left(n)
}
/// Keccak-f800 permutation round function.
///
/// This function performs a single round of the Keccak-f800 permutation on the state array.
/// It applies the `Theta`, `Rho`, `Pi`, and `Chi` transformations, followed by the round constant addition.
///
/// # Arguments
///
/// * `st` - A mutable reference to the 25-element state array.
/// * `r` - The round index (0-23), used to select the round constant.
///
/// # Notes
/// This function is a core part of the Keccak algorithm, specifically for f800-bit permutations.
pub fn keccak_f800_round(st: &mut [u32; 25], r: usize) {
    // Rho offsets for rotation.
    let keccakf_rotc: [u32; 24] = [
        1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
    ];

    // Pi lane mappings.
    let keccakf_piln: [usize; 24] = [
        10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
    ];

    let mut bc = [0u32; 5]; // Temporary array for column parity calculations.

    // Theta step: Mix each column based on the XOR of all other columns.
    for i in 0..5 {
        bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
    }

    for i in 0..5 {
        let t = bc[(i + 4) % 5] ^ rotl32(bc[(i + 1) % 5], 1);
        for j in (0..25).step_by(5) {
            st[j + i] ^= t; // Apply the transformation to each column.
        }
    }

    // Rho and Pi steps: Rotate and rearrange lanes.
    let mut t = st[1];
    for (i, &j) in keccakf_piln.iter().enumerate() {
        bc[0] = st[j];
        st[j] = rotl32(t, keccakf_rotc[i]); // Rotate by the predefined offset.
        t = bc[0];
    }

    // Chi step: Nonlinear mixing of rows.
    for j in (0..25).step_by(5) {
        // Save current row in the temporary array.
        bc[0] = st[j + 0];
        bc[1] = st[j + 1];
        bc[2] = st[j + 2];
        bc[3] = st[j + 3];
        bc[4] = st[j + 4];

        // Apply the Chi transformation.
        st[j + 0] ^= !bc[1] & bc[2];
        st[j + 1] ^= !bc[2] & bc[3];
        st[j + 2] ^= !bc[3] & bc[4];
        st[j + 3] ^= !bc[4] & bc[0];
        st[j + 4] ^= !bc[0] & bc[1];
    }

    // Iota step: Add the round constant to the first word.
    st[0] ^= KECCAKF_RNDC[r];
}
