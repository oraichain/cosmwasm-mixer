// This file is part of Webb and was adapted from Arkworks.
//
// Copyright (C) 2021 Webb Technologies Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! A Plonk gadget implementation of the Sparse Merkle Tree data structure.
//! For more info on the Sparse Merkle Tree data structure, see the
//! documentation for our native implementation.
//!
//! ## Usage
//!
//! In this example we build a plonk circuit with a Sparse Merkle Tree.
//!
//! ```rust
//! use ark_bn254::{Bn254, Fr as Bn254Fr};
//! use ark_ec::TEModelParameters;
//! use ark_ed_on_bn254::{EdwardsParameters as JubjubParameters, Fq};
//! use ark_ff::PrimeField;
//! use ark_std::{test_rng, UniformRand};
//! use arkworks_native_gadgets::{
//! 	merkle_tree::SparseMerkleTree,
//! 	poseidon::{sbox::PoseidonSbox, Poseidon, PoseidonParameters},
//! };
//! use plonk_gadgets::{
//! 	merkle_tree::PathGadget,
//! 	poseidon::{FieldHasherGadget, PoseidonGadget},
//! };
//! use arkworks_utils::{
//! 	bytes_matrix_to_f, bytes_vec_to_f, poseidon_params::setup_poseidon_params, Curve,
//! };
//! use plonk_core::prelude::*;
//!
//! type PoseidonBn254 = Poseidon<Fq>;
//!
//! pub fn setup_params<F: PrimeField>(curve: Curve, exp: i8, width: u8) -> PoseidonParameters<F> {
//! 	let pos_data = setup_poseidon_params(curve, exp, width).unwrap();
//!
//! 	let mds_f = bytes_matrix_to_f(&pos_data.mds);
//! 	let rounds_f = bytes_vec_to_f(&pos_data.rounds);
//!
//! 	let pos = PoseidonParameters {
//! 		mds_matrix: mds_f,
//! 		round_keys: rounds_f,
//! 		full_rounds: pos_data.full_rounds,
//! 		partial_rounds: pos_data.partial_rounds,
//! 		sbox: PoseidonSbox(pos_data.exp),
//! 		width: pos_data.width,
//! 	};
//!
//! 	pos
//! }
//!
//! struct TestCircuit<
//! 	'a,
//! 	F: PrimeField,
//! 	P: TEModelParameters<BaseField = F>,
//! 	HG: FieldHasherGadget<F, P>,
//! 	const N: usize,
//! > {
//! 	leaves: &'a [F],
//! 	empty_leaf: &'a [u8],
//! 	hasher: &'a HG::Native,
//! }
//!
//! impl<
//! 		F: PrimeField,
//! 		P: TEModelParameters<BaseField = F>,
//! 		HG: FieldHasherGadget<F, P>,
//! 		const N: usize,
//! 	> Circuit<F, P> for TestCircuit<'_, F, P, HG, N>
//! {
//! 	const CIRCUIT_ID: [u8; 32] = [0xfe; 32];
//!
//! 	fn gadget(&mut self, composer: &mut StandardComposer<F, P>) -> Result<(), Error> {
//! 		let hasher_gadget = HG::from_native(composer, self.hasher.clone());
//!
//! 		let smt = SparseMerkleTree::<F, HG::Native, N>::new_sequential(
//! 			self.leaves,
//! 			&self.hasher,
//! 			self.empty_leaf,
//! 		)
//! 		.unwrap();
//! 		let path = smt.generate_membership_proof(0);
//! 		let root = path.calculate_root(&self.leaves[0], &self.hasher).unwrap();
//!
//! 		let path_gadget = PathGadget::<F, P, HG, N>::from_native(composer, path);
//! 		let root_var = composer.add_input(root);
//! 		let leaf_var = composer.add_input(self.leaves[0]);
//!
//! 		let res =
//! 			path_gadget.check_membership(composer, &root_var, &leaf_var, &hasher_gadget)?;
//! 		let one = composer.add_input(F::one());
//! 		composer.assert_equal(res, one);
//!
//! 		Ok(())
//! 	}
//!
//! 	fn padded_circuit_size(&self) -> usize {
//! 		1 << 13
//! 	}
//! }
//!
//! // Create the test circuit
//!
//! let rng = &mut test_rng();
//! let curve = Curve::Bn254;
//! let params = setup_params(curve, 5, 3);
//! let poseidon = PoseidonBn254 { params };
//! let leaves = [Fq::rand(rng), Fq::rand(rng), Fq::rand(rng)];
//! let empty_leaf = [0u8; 32];
//! let mut test_circuit = TestCircuit::<Bn254Fr, JubjubParameters, PoseidonGadget, 3usize> {
//! 	leaves: &leaves,
//! 	empty_leaf: &empty_leaf,
//! 	hasher: &poseidon,
//! };
//! ```

use crate::poseidon::FieldHasherGadget;
use ark_ec::models::TEModelParameters;
use ark_ff::PrimeField;
use ark_std::marker::PhantomData;
use arkworks_native_gadgets::merkle_tree::Path;
use plonk_core::{constraint_system::StandardComposer, error::Error, prelude::Variable};

#[derive(Clone)]
pub struct PathGadget<
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
    HG: FieldHasherGadget<F, P>,
    const N: usize,
> {
    path: [(Variable, Variable); N],
    _field: PhantomData<F>,
    _te: PhantomData<P>,
    _hg: PhantomData<HG>,
}

impl<
        F: PrimeField,
        P: TEModelParameters<BaseField = F>,
        HG: FieldHasherGadget<F, P>,
        const N: usize,
    > PathGadget<F, P, HG, N>
{
    pub fn from_native(
        composer: &mut StandardComposer<F, P>,
        native: Path<F, HG::Native, N>,
    ) -> Self {
        // Initialize the array
        let mut path_vars = [(composer.zero_var(), composer.zero_var()); N];

        for i in 0..N {
            path_vars[i] = (
                composer.add_input(native.path[i].0),
                composer.add_input(native.path[i].1),
            );
        }

        PathGadget {
            path: path_vars,
            _field: PhantomData,
            _te: PhantomData,
            _hg: PhantomData,
        }
    }

    pub fn check_membership(
        &self,
        composer: &mut StandardComposer<F, P>,
        root_hash: &Variable,
        leaf: &Variable,
        hasher: &HG,
    ) -> Result<Variable, Error> {
        let computed_root = self.calculate_root(composer, leaf, hasher)?;

        Ok(composer.is_eq_with_output(computed_root, *root_hash))
    }

    pub fn calculate_root(
        &self,
        composer: &mut StandardComposer<F, P>,
        leaf: &Variable,
        hash_gadget: &HG,
    ) -> Result<Variable, Error> {
        // Check levels between leaf level and root
        let mut previous_hash = *leaf;

        for (left_hash, right_hash) in self.path.iter() {
            // Check if previous_hash matches the correct current hash
            let previous_is_left = composer.is_eq_with_output(previous_hash, *left_hash);
            let left_or_right =
                composer.conditional_select(previous_is_left, *left_hash, *right_hash);
            composer.assert_equal(previous_hash, left_or_right);

            // Update previous_hash
            previous_hash = hash_gadget.hash_two(composer, left_hash, right_hash)?;
        }

        Ok(previous_hash)
    }

    pub fn get_index(
        &self,
        composer: &mut StandardComposer<F, P>,
        root_hash: &Variable,
        leaf: &Variable,
        hasher: &HG,
    ) -> Result<Variable, Error> {
        // First check that leaf is on path
        // let is_on_path = self.check_membership(composer, root_hash, leaf, hasher)?;
        let one = composer.add_input(F::one());
        // composer.assert_equal(is_on_path, one);

        let mut index = composer.add_input(F::zero());
        let mut two_power = composer.add_input(F::one());
        let mut right_value: Variable;

        // Check the levels between leaf level and root
        let mut previous_hash = *leaf;

        for (left_hash, right_hash) in self.path.iter() {
            // Check if previous hash is a left node
            let previous_is_left = composer.is_eq_with_output(previous_hash, *left_hash);
            right_value = composer.arithmetic_gate(|gate| {
                gate.witness(index, two_power, None).add(F::one(), F::one())
            });

            // Assign index based on whether prev hash is left or right
            index = composer.conditional_select(previous_is_left, index, right_value);
            two_power = composer
                .arithmetic_gate(|gate| gate.witness(two_power, one, None).mul(F::one().double()));

            previous_hash = hasher.hash_two(composer, left_hash, right_hash)?;
        }
        //This line confirms that the path is consistent with the given merkle root
        composer.assert_equal(previous_hash, *root_hash);

        Ok(index)
    }
}