pub use self::mixer_verifier::MixerVerifier;

#[allow(clippy::all)]
pub mod mixer_verifier {

    use ark_bn254::Bn254;
    use ark_ed_on_bn254::EdwardsParameters as JubjubParameters;
    use serde::{Deserialize, Serialize};

    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub struct MixerVerifier {
        vk_bytes: Vec<u8>,
        pvk_bytes: Vec<u8>,
    }

    #[derive(Debug)]
    pub enum Error {
        /// Returned if error verifying
        VerifierError,
    }

    /// The verifier result type.
    pub type Result<T> = core::result::Result<T, Error>;

    impl MixerVerifier {
        /// Constructor that initializes the `bool` value to the given `init_value`.
        /// Plonk require vk key and plonk vk keys
        pub fn new() -> Self {
            let vk_bytes = include_bytes!("../../../bn254/x5/vk_key.bin").to_vec();
            let pvk_bytes = include_bytes!("../../../bn254/x5/pvk_key.bin").to_vec();
            Self {
                vk_bytes,
                pvk_bytes,
            }
        }

        /// A message that can be called on instantiated contracts.
        /// This one flips the value of the stored `bool` from `true`
        /// to `false` and vice versa.
        pub fn verify(&self, public_inp_bytes: Vec<u8>, proof_bytes: Vec<u8>) -> Result<bool> {
            plonk_circuits::utils::verify::<Bn254, JubjubParameters>(
                self.pvk_bytes.as_slice(),
                self.vk_bytes.as_slice(),
                proof_bytes,
                public_inp_bytes,
            )
            .map_err(|_| Error::VerifierError)
        }
    }

    impl Default for MixerVerifier {
        fn default() -> Self {
            Self::new()
        }
    }
}

#[cfg(test)]
mod test {

    use arkworks_setups::common::{create_merkle_tree, setup_params};
    use plonk_circuits::mixer::MixerCircuit;
    use plonk_circuits::utils::{get_public_bytes, prove};
    use plonk_gadgets::add_public_input_variable;

    use std::time::Instant;
    // use ark_bls12_381::Bls12_381;
    use ark_bn254::Bn254;
    // use ark_ed_on_bls12_381::{EdwardsParameters as JubjubParameters, Fq};
    use ark_ed_on_bn254::{EdwardsParameters as JubjubParameters, Fq};
    use ark_ff::{PrimeField, UniformRand};
    use ark_std::rand::{self, SeedableRng};
    use arkworks_native_gadgets::poseidon::{FieldHasher, Poseidon};
    use arkworks_utils::Curve;
    use plonk_core::circuit::Circuit;
    use plonk_gadgets::poseidon::PoseidonGadget;

    use crate::mixer_verifier::MixerVerifier;

    type PoseidonHash = Poseidon<Fq>;

    #[test]
    fn should_verify_correct_mixer_plonk() {
        // arbitrary seed
        let mut seed = [0u8; 32];

        getrandom::getrandom(&mut seed).unwrap();

        let rng = &mut rand::rngs::StdRng::from_seed(seed);

        // let poseidon_native = PoseidonHash { params };
        let params = setup_params(Curve::Bn254, 5, 3);
        let poseidon_native = Poseidon::new(params);

        let note_secret = "7e0f4bfa263d8b93854772c94851c04b3a9aba38ab808a8d081f6f5be9758110b7147c395ee9bf495734e4703b1f622009c81712520de0bbd5e7a10237c7d829bf6bd6d0729cca778ed9b6fb172bbb12b01927258aca7e0a66fd5691548f8717";
        let raw = hex::decode(&note_secret).unwrap();

        let secret = Fq::from_le_bytes_mod_order(&raw[0..32]);
        let nullifier = Fq::from_le_bytes_mod_order(&raw[32..64]);

        // Public data
        let arbitrary_data = Fq::rand(rng);

        let nullifier_hash = poseidon_native.hash_two(&nullifier, &nullifier).unwrap();
        let leaf_hash = poseidon_native.hash_two(&secret, &nullifier).unwrap();

        const TREE_HEIGHT: usize = 30usize;
        let last_index = 0;
        let leaves = [leaf_hash];

        let tree = create_merkle_tree::<Fq, PoseidonHash, TREE_HEIGHT>(
            &poseidon_native,
            &leaves,
            &[0u8; 32],
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

        let ck_bytes = include_bytes!("../../../bn254/x5/ck_key.bin");

        let mv = MixerVerifier::new();

        // Prove then verify
        let proof_bytes =
            prove::<Bn254, JubjubParameters, _>(&mut |c| mixer.gadget(c), ck_bytes).unwrap();

        let public_bytes = get_public_bytes::<Bn254, JubjubParameters, _>(&mut |c| {
            Ok({
                // Public Inputs
                add_public_input_variable(c, nullifier_hash);
                add_public_input_variable(c, root);
                add_public_input_variable(c, arbitrary_data);
            })
        })
        .unwrap();

        let start = Instant::now();

        let res = mv.verify(public_bytes, proof_bytes);
        let elapsed = start.elapsed();

        // Debug format
        println!("Verify took: {:?}", elapsed);

        match res {
            Ok(_b) => (),
            Err(err) => panic!("Unexpected error: {:?}", err),
        };
    }
}
