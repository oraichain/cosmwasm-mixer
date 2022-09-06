use ark_crypto_primitives::Error;
use ark_ff::fields::PrimeField;
use ark_std::{collections::BTreeMap, vec::Vec};
use arkworks_native_gadgets::{
    merkle_tree::{Path, SparseMerkleTree},
    poseidon::{sbox::PoseidonSbox, FieldHasher, PoseidonParameters},
};
use arkworks_utils::{
    bytes_matrix_to_f, bytes_vec_to_f, poseidon_params::setup_poseidon_params, Curve,
};
use tiny_keccak::{Hasher, Keccak};

pub fn keccak_256(input: &[u8]) -> Vec<u8> {
    let mut keccak = Keccak::v256();
    keccak.update(&input);

    let mut output = [0u8; 32];
    keccak.finalize(&mut output);
    output.to_vec()
}

pub type SMT<F, H, const HEIGHT: usize> = SparseMerkleTree<F, H, HEIGHT>;

pub fn create_merkle_tree<F: PrimeField, H: FieldHasher<F>, const N: usize>(
    hasher: &H,
    leaves: &[F],
    default_leaf: &[u8],
) -> SparseMerkleTree<F, H, N> {
    let pairs: BTreeMap<u32, F> = leaves
        .iter()
        .enumerate()
        .map(|(i, l)| (i as u32, *l))
        .collect();
    let smt = SparseMerkleTree::<F, H, N>::new(&pairs, hasher, default_leaf).unwrap();

    smt
}

pub fn setup_tree_and_create_path<F: PrimeField, H: FieldHasher<F>, const HEIGHT: usize>(
    hasher: &H,
    leaves: &[F],
    index: u64,
    default_leaf: &[u8],
) -> Result<(SMT<F, H, HEIGHT>, Path<F, H, HEIGHT>), Error> {
    // Making the merkle tree
    let smt = create_merkle_tree::<F, H, HEIGHT>(hasher, leaves, default_leaf);
    // Getting the proof path
    let path = smt.generate_membership_proof(index);
    Ok((smt, path))
}

pub fn setup_params<F: PrimeField>(curve: Curve, exp: i8, width: u8) -> PoseidonParameters<F> {
    let pos_data = setup_poseidon_params(curve, exp, width).unwrap();

    let mds_f = bytes_matrix_to_f(&pos_data.mds);
    let rounds_f = bytes_vec_to_f(&pos_data.rounds);

    let pos = PoseidonParameters {
        mds_matrix: mds_f,
        round_keys: rounds_f,
        full_rounds: pos_data.full_rounds,
        partial_rounds: pos_data.partial_rounds,
        sbox: PoseidonSbox(pos_data.exp),
        width: pos_data.width,
    };

    pos
}
