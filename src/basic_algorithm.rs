/// Total number of bytes in the ProgPoW cache.
pub const PROGPOW_CACHE_BYTES: usize = 16 * 1024;

/// Total number of 32-bit words in the ProgPoW cache.
pub const PROGPOW_CACHE_WORDS: usize = PROGPOW_CACHE_BYTES / 4;

/// Number of parallel lanes in ProgPoW.
pub const PROGPOW_LANES: usize = 16;

/// Number of registers in each lane.
pub const PROGPOW_REGS: usize = 32;

/// Number of DAG loads performed per loop.
pub const PROGPOW_DAG_LOADS: usize = 4;

/// Number of cache accesses per loop.
pub const PROGPOW_CNT_CACHE: usize = 11;

/// Number of mathematical operations per loop.
pub const PROGPOW_CNT_MATH: usize = 18;

/// Number of DAG accesses per computation.
pub const PROGPOW_CNT_DAG: usize = 64;

/// Number of bytes in the ProgPoW mix buffer.
pub const PROGPOW_MIX_BYTES: usize = 256;

/// Length of the period for block processing.
pub const PROGPOW_PERIOD_LENGTH: u64 = u64::max_value();

use byteorder::{ByteOrder, LittleEndian};

#[derive(Default)]
pub struct Kiss99State {
    z: u32,
    w: u32,
    jsr: u32,
    jcong: u32,
}

/// Computes the FNV-1a hash.
///
/// This is used for hashing small inputs in ProgPoW, such as seeds and indices.
///
/// # Arguments
///
/// * `h` - A mutable reference to the current hash value.
/// * `d` - The data to be hashed.
///
/// # Returns
///
/// The updated hash value.
pub fn fnv1a(h: &mut u32, d: u32) -> u32 {
    *h = (*h ^ d).wrapping_mul(0x1000193);
    *h
}

/// Generates a pseudo-random number using the KISS99 algorithm.
///
/// This is used as a lightweight random number generator in ProgPoW.
///
/// # Arguments
///
/// * `st` - A mutable reference to the KISS99 state.
///
/// # Returns
///
/// A 32-bit pseudo-random number.
pub fn kiss99(st: &mut Kiss99State) -> u32 {
    st.z = 36969 * (st.z & 65535) + (st.z >> 16);
    st.w = 18000 * (st.w & 65535) + (st.w >> 16);
    let mwc = (st.z << 16).wrapping_add(st.w);
    st.jsr ^= st.jsr.wrapping_shl(17);
    st.jsr ^= st.jsr.wrapping_shr(13);
    st.jsr ^= st.jsr.wrapping_shl(5);
    st.jcong = st.jcong.wrapping_mul(69069).wrapping_add(1234567);
    (mwc ^ st.jcong).wrapping_add(st.jsr)
}
/// Extracts the lower 32 bits of a 64-bit integer.
///
/// # Arguments
///
/// * `n` - The 64-bit integer.
///
/// # Returns
///
/// The lower 32 bits as a `u32`.
pub fn lower32(n: u64) -> u32 {
    n as u32
}
/// Extracts the higher 32 bits of a 64-bit integer.
///
/// # Arguments
///
/// * `n` - The 64-bit integer.
///
/// # Returns
///
/// The higher 32 bits as a `u32`.
pub fn higher32(n: u64) -> u32 {
    (n >> 32) as u32
}
/// Performs a left rotation on a 32-bit integer.
///
/// # Arguments
///
/// * `x` - The value to rotate.
/// * `n` - The number of bits to rotate.
///
/// # Returns
///
/// The rotated value.
pub fn rotl32(x: u32, n: u32) -> u32 {
    x.rotate_left(n)
}
/// Performs a right rotation on a 32-bit integer.
///
/// # Arguments
///
/// * `x` - The value to rotate.
/// * `n` - The number of bits to rotate.
///
/// # Returns
///
/// The rotated value.
pub fn rotr32(x: u32, n: u32) -> u32 {
    x.rotate_right(n % 32)
}
/// Fills the mix registers for a given lane with random values.
///
/// # Arguments
///
/// * `seed` - The seed for random number generation.
/// * `lane_id` - The ID of the lane to initialize.
///
/// # Returns
///
/// An array of `PROGPOW_REGS` 32-bit integers representing the initialized mix.
pub fn fill_mix(seed: u64, lane_id: u32) -> [u32; PROGPOW_REGS] {
    let mut st = Kiss99State {
        z: 0,
        w: 0,
        jsr: 0,
        jcong: 0,
    };
    let mut mix = [0u32; PROGPOW_REGS];
    let mut fnv_hash = 0x811c9dc5;

    st.z = fnv1a(&mut fnv_hash, lower32(seed));
    st.w = fnv1a(&mut fnv_hash, higher32(seed));
    st.jsr = fnv1a(&mut fnv_hash, lane_id);
    st.jcong = fnv1a(&mut fnv_hash, lane_id);
    println!(
        "state: z: {}, w: {}, jsr: {}, jcong: {}",
        st.z, st.w, st.jsr, st.jcong
    );

    for i in 0..PROGPOW_REGS {
        mix[i] = kiss99(&mut st);
    }
    mix
}
/// Performs a mathematical operation based on a given opcode.
///
/// This function implements various mathematical and bitwise operations.
///
/// # Arguments
///
/// * `a` - The first operand.
/// * `b` - The second operand.
/// * `r` - A random value that determines the operation.
///
/// # Returns
///
/// The result of the operation.
fn progpow_math(a: u32, b: u32, r: u32) -> u32 {
    match r % 11 {
        0 => a.wrapping_add(b),
        1 => a.wrapping_mul(b),
        2 => higher32((a as u64).wrapping_mul(b as u64)),
        3 => {
            if a < b {
                a
            } else {
                b
            }
        }
        4 => rotl32(a, b),
        5 => rotr32(a, b),
        6 => a & b,
        7 => a | b,
        8 => a ^ b,
        9 => (a.leading_zeros() + b.leading_zeros()) as u32,
        10 => (a.count_ones() + b.count_ones()) as u32,
        _ => 0,
    }
}
/// Merges a value into a destination register using a specific operation.
///
/// # Arguments
///
/// * `a` - A mutable reference to the destination register.
/// * `b` - The value to merge.
/// * `r` - A random value that determines the operation.
fn merge(a: &mut u32, b: u32, r: u32) {
    match r % 4 {
        0 => *a = (*a).wrapping_mul(33).wrapping_add(b),
        1 => *a = (*a ^ b).wrapping_mul(33),
        2 => *a = rotl32(*a, ((r >> 16) % 31) + 1) ^ b,
        _ => *a = rotr32(*a, ((r >> 16) % 31) + 1) ^ b,
    }
}
/// Initializes the ProgPoW random state and sequence.
///
/// This function generates random sequences for accessing registers during the loop.
///
/// # Arguments
///
/// * `seed` - The seed for random number generation.
///
/// # Returns
///
/// A tuple containing:
/// 1. The initialized `Kiss99State`.
/// 2. The destination register sequence.
/// 3. The source register sequence.
pub fn progpow_init(seed: u64) -> (Kiss99State, [u32; PROGPOW_REGS], [u32; PROGPOW_REGS]) {
    let mut rand_state = Kiss99State::default();
    let fnv_hash = &mut 0x811c9dc5u32;

    rand_state.z = fnv1a(fnv_hash, lower32(seed));
    rand_state.w = fnv1a(fnv_hash, higher32(seed));
    rand_state.jsr = fnv1a(fnv_hash, lower32(seed));
    rand_state.jcong = fnv1a(fnv_hash, higher32(seed));

    let mut dst_seq: [u32; PROGPOW_REGS] = (0..PROGPOW_REGS as u32)
        .collect::<Vec<u32>>()
        .try_into()
        .unwrap();
    let mut src_seq: [u32; PROGPOW_REGS] = (0..PROGPOW_REGS as u32)
        .collect::<Vec<u32>>()
        .try_into()
        .unwrap();

    for i in (1..PROGPOW_REGS).rev() {
        let j = kiss99(&mut rand_state) % (i as u32 + 1);
        dst_seq.swap(i, j as usize);

        let j = kiss99(&mut rand_state) % (i as u32 + 1);
        src_seq.swap(i, j as usize);
    }

    (rand_state, dst_seq, src_seq)
}
/// Executes a single loop of the ProgPoW computation.
///
/// This function performs memory accesses, random math operations, and merges results into the mix.
///
/// # Arguments
///
/// * `seed` - The seed for random number generation.
/// * `loop_index` - The index of the current loop iteration.
/// * `mix` - A mutable reference to the mix data.
/// * `lookup` - A function to retrieve DAG items based on an index.
/// * `c_dag` - The compressed DAG data.
/// * `dataset_size` - The size of the dataset.
///
/// # Notes
///
/// This function is the core of the ProgPoW hashing algorithm.
pub fn progpow_loop(
    seed: u64,
    loop_index: u32,
    mix: &mut [[u32; PROGPOW_REGS]; PROGPOW_LANES],
    lookup: &dyn Fn(u32) -> Vec<u8>,
    c_dag: &[u32],
    dataset_size: u32,
) {
    let g_offset = mix[loop_index as usize % PROGPOW_LANES][0]
        % (64 * dataset_size / (PROGPOW_LANES as u32 * PROGPOW_DAG_LOADS as u32));

    let mut dst_counter: u32 = 0;
    let mut rand_state = Kiss99State {
        z: 0,
        w: 0,
        jsr: 0,
        jcong: 0,
    };

    //检查数据
    println!("g_offset: {}", g_offset);

    let mut src_seq = [0u32; PROGPOW_REGS];
    let mut dst_seq = [0u32; PROGPOW_REGS];
    let mut data_g = [0u32; PROGPOW_DAG_LOADS];
    let mut dag_item = vec![0u8; 256];

    dag_item[0..64]
        .copy_from_slice(&lookup((g_offset * PROGPOW_LANES as u32) * PROGPOW_DAG_LOADS as u32)[..]);
    dag_item[64..128].copy_from_slice(
        &lookup((g_offset * PROGPOW_LANES as u32) * PROGPOW_DAG_LOADS as u32 + 16)[..],
    );
    dag_item[128..192].copy_from_slice(
        &lookup((g_offset * PROGPOW_LANES as u32) * PROGPOW_DAG_LOADS as u32 + 32)[..],
    );
    dag_item[192..].copy_from_slice(
        &lookup((g_offset * PROGPOW_LANES as u32) * PROGPOW_DAG_LOADS as u32 + 48)[..],
    );

    for l in 0..PROGPOW_LANES as u32 {
        // Initialize the seed and mix destination sequence
        let mut src_counter: u32 = 0;
        let (mut rand_state, dst_seq, src_seq) = progpow_init(seed);
        // println!("dst_seq: {:?}, src_seq: {:?}", dst_seq, src_seq);
        for i in 0..PROGPOW_CNT_MATH {
            if i < PROGPOW_CNT_CACHE {
                // Cached memory access
                let src = src_seq[(src_counter % PROGPOW_REGS as u32) as usize];
                // println!("{}", (src_counter % PROGPOW_REGS as u32) as usize);
                src_counter += 1;
                // println!("Lane {} Cache Access: src={}", l, src);

                let offset = mix[l as usize][src as usize] % PROGPOW_CACHE_WORDS as u32;
                let data32 = c_dag[offset as usize];

                let dst = dst_seq[(dst_counter % PROGPOW_REGS as u32) as usize];
                dst_counter += 1;

                let r = kiss99(&mut rand_state);
                merge(&mut mix[l as usize][dst as usize], data32, r);
                // println!(
                //     "Lane {} Cache Access: offset={}, data32={}, dst={}, mix[dst]={}",
                //     l, offset, data32, dst, mix[l as usize][dst as usize]
                // );
            }

            // Random Math
            let src_rnd = kiss99(&mut rand_state) % (PROGPOW_REGS * (PROGPOW_REGS - 1)) as u32;
            let src1 = src_rnd % PROGPOW_REGS as u32;
            let mut src2 = src_rnd / PROGPOW_REGS as u32;
            if src2 >= src1 {
                src2 += 1;
            }
            let data32 = progpow_math(
                mix[l as usize][src1 as usize],
                mix[l as usize][src2 as usize],
                kiss99(&mut rand_state),
            );

            let dst = dst_seq[(dst_counter % PROGPOW_REGS as u32) as usize];
            dst_counter += 1;

            merge(
                &mut mix[l as usize][dst as usize],
                data32,
                kiss99(&mut rand_state),
            );
        }

        let index = ((l ^ loop_index) % PROGPOW_LANES as u32) * PROGPOW_DAG_LOADS as u32;

        data_g[0] = LittleEndian::read_u32(&dag_item[(4 * index) as usize..]);
        data_g[1] = LittleEndian::read_u32(&dag_item[(4 * (index + 1)) as usize..]);
        data_g[2] = LittleEndian::read_u32(&dag_item[(4 * (index + 2)) as usize..]);
        data_g[3] = LittleEndian::read_u32(&dag_item[(4 * (index + 3)) as usize..]);

        merge(&mut mix[l as usize][0], data_g[0], kiss99(&mut rand_state));

        for i in 1..PROGPOW_DAG_LOADS {
            let dst = dst_seq[(dst_counter % PROGPOW_REGS as u32) as usize];
            dst_counter += 1;
            merge(
                &mut mix[l as usize][dst as usize],
                data_g[i],
                kiss99(&mut rand_state),
            );
        }
    }
}
