use std::fs;

use ckb_vm::RISCV_MAX_MEMORY;
use rand::Rng;

pub mod common;
pub mod machine;
pub mod memory;
pub mod prover;
pub mod types;
pub mod verifier;

use crate::{prover::Prover, verifier::Verifier};

fn main() {
    let mut prover = Prover::<u32>::new(RISCV_MAX_MEMORY);
    let buffer = fs::read("./simple").unwrap().into();
    prover.load_program(&buffer).unwrap();

    let result = prover.run().unwrap();
    println!("step count: {}", result.step_count);

    prover.reset();
    prover.load_program(&buffer).unwrap();

    let random_step = rand::rngs::OsRng::default().gen::<u64>() % (result.step_count - 1);
    let next_step = random_step + 1;
    println!("random step {}", random_step);
    let step_commitment = *result.step_commitments.get(random_step as usize).unwrap();
    let next_step_commitment = *result.step_commitments.get(next_step as usize).unwrap();

    let result = prover.run_until_step(random_step).unwrap();
    assert_eq!(result.step_count, random_step);

    let proof = prover.prove_next_step().unwrap();
    let mut verifier = Verifier::<u32>::from_proof(proof).unwrap();
    assert_eq!(step_commitment, verifier.commit_step().unwrap());

    verifier.execute_next_step().unwrap();
    assert_eq!(next_step_commitment, verifier.commit_step().unwrap());
}
