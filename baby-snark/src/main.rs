use baby_snark::{
    scs::SquareConstraintSystem, setup, ssp::SquareSpanProgram, utils::i64_vec_to_field, verify,
    Prover,
};

fn main() {
    let u = vec![
        i64_vec_to_field(&[-1, 2, 0, 0]),
        i64_vec_to_field(&[-1, 0, 2, 0]),
        i64_vec_to_field(&[-1, 0, 0, 2]),
        i64_vec_to_field(&[-1, 2, 2, -4]),
    ];
    let witness = i64_vec_to_field(&[1, 1, 1]);
    let public = i64_vec_to_field(&[1]);

    let mut input = public.clone();
    input.extend(witness.clone());

    let ssp = SquareSpanProgram::from_scs(SquareConstraintSystem::from_matrix(u, public.len()));

    let (pk, vk) = setup(&ssp);
    let proof = Prover::prove(&input, &ssp, &pk).unwrap();

    let verified = verify(&vk, &proof, &public);
    assert!(verified);
}
