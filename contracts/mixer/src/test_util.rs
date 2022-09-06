use ark_bn254::Bn254;

use ark_ff::BigInteger;
use ark_ff::PrimeField;
use arkworks_native_gadgets::poseidon::FieldHasher;
use arkworks_native_gadgets::poseidon::Poseidon;
use arkworks_setups::common::create_merkle_tree;
use arkworks_setups::common::keccak_256;
use arkworks_setups::common::setup_params;
use arkworks_utils::Curve;
use plonk_gadgets::poseidon::PoseidonGadget;

use ark_ed_on_bn254::{EdwardsParameters as JubjubParameters, Fq};
use plonk_circuits::mixer::MixerCircuit;
use plonk_circuits::utils::prove;
use plonk_core::circuit::Circuit;
use wasm_utils::{DEFAULT_LEAF, TREE_HEIGHT};

pub fn setup_wasm_utils_zk_circuit(
    ck_bytes: &[u8],
    recipient_bytes: Vec<u8>,
    relayer_bytes: Vec<u8>,
    fee_value: u128,
    refund_value: u128,
) -> (
    Vec<u8>, // proof
    Vec<u8>, // root
    Vec<u8>, // nullifier
    Vec<u8>, // commitment
) {
    let params = setup_params(Curve::Bn254, 5, 3);
    let poseidon_native = Poseidon::new(params);

    let note_secret = "7e0f4bfa263d8b93854772c94851c04b3a9aba38ab808a8d081f6f5be9758110b7147c395ee9bf495734e4703b1f622009c81712520de0bbd5e7a10237c7d829bf6bd6d0729cca778ed9b6fb172bbb12b01927258aca7e0a66fd5691548f8717";
    let raw = hex::decode(&note_secret).unwrap();

    let secret = Fq::from_le_bytes_mod_order(&raw[0..32]);
    let nullifier = Fq::from_le_bytes_mod_order(&raw[32..64]);

    // Public data
    let mut arbitrary_data_bytes = Vec::new();
    arbitrary_data_bytes.extend(&recipient_bytes);
    arbitrary_data_bytes.extend(&relayer_bytes);
    // Using encode to be compatible with on chain types
    arbitrary_data_bytes.extend(fee_value.to_le_bytes());
    arbitrary_data_bytes.extend(refund_value.to_le_bytes());

    let arbitrary_data = Fq::from_le_bytes_mod_order(&keccak_256(&arbitrary_data_bytes));

    let nullifier_hash = poseidon_native.hash_two(&nullifier, &nullifier).unwrap();
    let leaf_hash = poseidon_native.hash_two(&secret, &nullifier).unwrap();

    let last_index = 0;
    let leaves = [leaf_hash];

    let tree = create_merkle_tree::<Fq, Poseidon<Fq>, TREE_HEIGHT>(
        &poseidon_native,
        &leaves,
        &DEFAULT_LEAF,
    );
    let root = tree.root();

    // Path
    let path = tree.generate_membership_proof(last_index as u64);

    // Create MixerCircuit
    let mut mixer = MixerCircuit::<Fq, JubjubParameters, PoseidonGadget, TREE_HEIGHT>::new(
        secret,
        nullifier,
        nullifier_hash,
        path,
        root,
        arbitrary_data,
        poseidon_native,
    );

    let commitment = leaf_hash.into_repr().to_bytes_le();
    let root_bytes = root.into_repr().to_bytes_le();
    // Prove then verify
    let proof_bytes =
        prove::<Bn254, JubjubParameters, _>(&mut |c| mixer.gadget(c), ck_bytes).unwrap();
    (
        proof_bytes,
        root_bytes,
        nullifier_hash.into_repr().to_bytes_le(),
        commitment,
    )
}
