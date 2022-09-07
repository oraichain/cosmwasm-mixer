use ark_bn254::Bn254;
use ark_ed_on_bn254::{EdwardsParameters as JubjubParameters, Fq};

use ark_std::rand::{self};
use arkworks_native_gadgets::{
    ark_std::UniformRand,
    merkle_tree::SparseMerkleTree,
    poseidon::{FieldHasher, Poseidon},
};
use arkworks_setups::common::setup_params;
use plonk_circuits::mixer::MixerCircuit;
use plonk_circuits::utils::{gen_keys, get_pvk};
use plonk_core::prelude::*;
use plonk_gadgets::poseidon::PoseidonGadget;
use std::{env::current_dir, fs::write, path::Path};

// type PoseidonHash = Poseidon<Fq>;
type PoseidonHash = Poseidon<Fq>;

fn main() {
    // arbitrary seed
    let rng = &mut rand::rngs::OsRng;

    let params = setup_params(5, 3);
    let poseidon_native = PoseidonHash { params };

    // Randomly generated secrets
    let secret = Fq::rand(rng);
    let nullifier = Fq::rand(rng);

    // Public data
    let arbitrary_data = Fq::rand(rng);
    let nullifier_hash = poseidon_native.hash_two(&nullifier, &nullifier).unwrap();
    let leaf_hash = poseidon_native.hash_two(&secret, &nullifier).unwrap();

    // Create a tree whose leaves are already populated with 2^HEIGHT - 1 random
    // scalars, then add leaf_hash as the final leaf
    // seed data with height 6
    const HEIGHT: usize = 6usize;
    const TREE_HEIGHT: usize = 30usize;
    let last_index = 1 << (HEIGHT - 1) - 1;
    let mut leaves = [Fq::from(0u8); 1 << (HEIGHT - 1)];
    for i in 0..last_index {
        leaves[i] = Fq::rand(rng);
    }
    leaves[last_index] = leaf_hash;
    let tree = SparseMerkleTree::<Fq, PoseidonHash, TREE_HEIGHT>::new_sequential(
        &leaves,
        &poseidon_native,
        &[0u8; 32],
    )
    .unwrap();
    let root = tree.root();

    // Path
    let membership_path = tree.generate_membership_proof(last_index as u64);

    // Create MixerCircuit
    let mut mixer = MixerCircuit::<Fq, JubjubParameters, PoseidonGadget, TREE_HEIGHT>::new(
        secret,
        nullifier,
        nullifier_hash,
        membership_path,
        root,
        arbitrary_data,
        poseidon_native,
    );

    let (ck_bytes, vk_bytes) = gen_keys::<Bn254, _>(rng, 1 << 17);

    let pvk_bytes =
        get_pvk::<Bn254, JubjubParameters, _>(&mut |c| mixer.gadget(c), ck_bytes.as_slice())
            .unwrap();

    let current_path = Path::new(&current_dir().unwrap())
        .join("..")
        .join("..")
        .join("bn254")
        .join("x5");

    write(current_path.clone().join("vk_key.bin"), vk_bytes).unwrap();
    write(current_path.clone().join("ck_key.bin"), ck_bytes).unwrap();
    write(current_path.clone().join("pvk_key.bin"), pvk_bytes).unwrap();
}
