use ark_ec::models::TEModelParameters;
use ark_ff::PrimeField;
use arkworks_native_gadgets::merkle_tree::Path;
use plonk_core::{circuit::Circuit, constraint_system::StandardComposer, error::Error};
use plonk_gadgets::{
    add_public_input_variable, merkle_tree::PathGadget, poseidon::FieldHasherGadget,
};

pub struct MixerCircuit<
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
    HG: FieldHasherGadget<F, P>,
    const N: usize,
> {
    secret: F,
    nullifier: F,
    nullifier_hash: F,
    path: Path<F, HG::Native, N>,
    root: F,
    arbitrary_data: F,
    hasher: HG::Native,
}

impl<F, P, HG, const N: usize> MixerCircuit<F, P, HG, N>
where
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
    HG: FieldHasherGadget<F, P>,
{
    pub fn new(
        secret: F,
        nullifier: F,
        nullifier_hash: F,
        path: Path<F, HG::Native, N>,
        root: F,
        arbitrary_data: F,
        hasher: HG::Native,
    ) -> Self {
        Self {
            secret,
            nullifier,
            nullifier_hash,
            path,
            root,
            arbitrary_data,
            hasher,
        }
    }
}

impl<F, P, HG, const N: usize> Circuit<F, P> for MixerCircuit<F, P, HG, N>
where
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
    HG: FieldHasherGadget<F, P>,
{
    const CIRCUIT_ID: [u8; 32] = [0xff; 32];

    fn gadget(&mut self, composer: &mut StandardComposer<F, P>) -> Result<(), Error> {
        // Private Inputs
        let secret = composer.add_input(self.secret);
        let nullifier = composer.add_input(self.nullifier);
        let path_gadget = PathGadget::<F, P, HG, N>::from_native(composer, self.path.clone());

        // Public Inputs
        let nullifier_hash = add_public_input_variable(composer, self.nullifier_hash);
        let root = add_public_input_variable(composer, self.root);
        let arbitrary_data = add_public_input_variable(composer, self.arbitrary_data);

        // Create the hasher_gadget from native
        let hasher_gadget: HG =
            FieldHasherGadget::<F, P>::from_native(composer, self.hasher.clone());

        // Preimage proof of nullifier
        let res_nullifier = hasher_gadget.hash_two(composer, &nullifier, &nullifier)?;
        // TODO: (This has 1 more gate than skipping the nullifier_hash variable and
        // putting this straight in to a poly_gate)
        composer.assert_equal(res_nullifier, nullifier_hash);

        // Preimage proof of leaf hash
        let res_leaf = hasher_gadget.hash_two(composer, &secret, &nullifier)?;

        // Proof of Merkle tree membership
        let is_member = path_gadget.check_membership(composer, &root, &res_leaf, &hasher_gadget)?;
        let one = composer.add_witness_to_circuit_description(F::one());
        composer.assert_equal(is_member, one);

        // Safety constraint to prevent tampering with arbitrary_data
        let _arbitrary_data_squared = composer.arithmetic_gate(|gate| {
            gate.witness(arbitrary_data, arbitrary_data, None)
                .mul(F::one())
        });
        Ok(())
    }

    fn padded_circuit_size(&self) -> usize {
        1 << 21
    }
}