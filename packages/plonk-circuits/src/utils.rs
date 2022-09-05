use ark_ec::{models::TEModelParameters, PairingEngine};
use ark_poly::polynomial::univariate::DensePolynomial;
use ark_poly_commit::{
    kzg10::UniversalParams,
    sonic_pc::{CommitterKey, SonicKZG10, VerifierKey},
    PolynomialCommitment,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use plonk_core::{
    prelude::*,
    proof_system::{pi::PublicInputs, Prover, Verifier, VerifierKey as PlonkVerifierKey},
};

use ark_std::rand::RngCore;

pub fn gen_keys<E: PairingEngine, R: RngCore>(
    rng: &mut R,
    max_degree: usize,
) -> (Vec<u8>, Vec<u8>) {
    // Go through proof generation/verification
    let u_params: UniversalParams<E> =
        SonicKZG10::<E, DensePolynomial<E::Fr>>::setup(max_degree, None, rng).unwrap();
    // Compute Commit and Verifier key
    let (ck, vk) =
        SonicKZG10::<E, DensePolynomial<E::Fr>>::trim(&u_params, max_degree, 0, None).unwrap();

    let mut ck_bytes = vec![];
    let mut vk_bytes = vec![];
    ck.serialize(&mut ck_bytes).unwrap();
    vk.serialize(&mut vk_bytes).unwrap();

    (ck_bytes, vk_bytes)
}

/// Helper function that accepts a composer that has already been filled,
/// generates a proof, then verifies it.
/// Accepts an optional public input argument that can be used to simulate
/// a situation where prover and verifier disagree on public input values
pub fn prove<
    E: PairingEngine,
    P: TEModelParameters<BaseField = E::Fr>,
    T: FnMut(&mut StandardComposer<E::Fr, P>) -> Result<(), Error>,
>(
    // gadget: fn(&mut StandardComposer<E::Fr, P>),
    gadget: &mut T,
    ck_bytes: &[u8],
) -> Result<Vec<u8>, Error> {
    let ck = CommitterKey::deserialize(ck_bytes).unwrap();

    let proof = {
        // Create a prover struct
        let mut prover =
            Prover::<E::Fr, P, SonicKZG10<E, DensePolynomial<E::Fr>>>::new(b"test circuit");
        prover.key_transcript(b"key", b"additional seed information");
        // Add gadgets
        let _ = gadget(prover.mut_cs());

        // Preprocess circuit
        let _ = prover.preprocess(&ck);
        // Compute Proof
        prover.prove(&ck)?
    };
    let mut proof_bytes = vec![];
    proof.serialize(&mut proof_bytes).unwrap();

    Ok(proof_bytes)
}

pub fn get_public_bytes<
    E: PairingEngine,
    P: TEModelParameters<BaseField = E::Fr>,
    T: FnMut(&mut StandardComposer<E::Fr, P>) -> Result<(), Error>,
>(
    // gadget: fn(&mut StandardComposer<E::Fr, P>),
    gadget: &mut T,
) -> Result<Vec<u8>, Error> {
    // Fill a composer to extract the public_inputs
    let mut composer = StandardComposer::<E::Fr, P>::new();
    let _ = gadget(&mut composer);
    let public_inputs = composer.get_pi().to_owned();

    let mut public_bytes = vec![];
    public_inputs.serialize(&mut public_bytes).unwrap();

    Ok(public_bytes)
}

pub fn get_pvk<
    E: PairingEngine,
    P: TEModelParameters<BaseField = E::Fr>,
    T: FnMut(&mut StandardComposer<E::Fr, P>) -> Result<(), Error>,
>(
    gadget: &mut T,
    ck_bytes: &[u8],
) -> Result<Vec<u8>, Error> {
    // Verifier's view

    // Create a Verifier object

    let mut verifier =
        Verifier::<E::Fr, P, SonicKZG10<E, DensePolynomial<E::Fr>>>::new(b"test circuit");
    verifier.key_transcript(b"key", b"additional seed information");
    // Add gadgets
    let _ = gadget(verifier.mut_cs());

    let ck = CommitterKey::deserialize(ck_bytes).unwrap();

    // Preprocess circuit
    verifier.preprocess(&ck)?;
    let mut pvk_bytes = vec![];
    verifier
        .verifier_key
        .as_ref()
        .unwrap()
        .serialize(&mut pvk_bytes)
        .unwrap();

    Ok(pvk_bytes)
}

pub fn verify<E: PairingEngine, P: TEModelParameters<BaseField = E::Fr>>(
    pvk_bytes: &[u8],
    vk_bytes: &[u8],
    proof_bytes: Vec<u8>,
    public_bytes: Vec<u8>,
) -> Result<bool, Error> {
    let vk = VerifierKey::deserialize(vk_bytes).unwrap();
    let verifier_key = PlonkVerifierKey::deserialize(pvk_bytes).unwrap();

    let proof = Proof::deserialize(proof_bytes.as_slice()).unwrap();

    let mut verifier =
        Verifier::<E::Fr, P, SonicKZG10<E, DensePolynomial<E::Fr>>>::new(b"test circuit");
    verifier.key_transcript(b"key", b"additional seed information");

    // post proof + verifier key + vk + public input
    verifier.verifier_key = Some(verifier_key);
    verifier.seed_transcript().unwrap();

    let public_inputs = PublicInputs::deserialize(public_bytes.as_slice()).unwrap();

    // Verify proof

    verifier.verify(&proof, &vk, &public_inputs)?;

    Ok(true)
}
